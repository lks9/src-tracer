#!/usr/bin/env python3

import sys

from clang.cindex import Index, CursorKind


class Instrumenter:

    def __init__(self, functions=None):
        if functions:
            self.functions = functions
        else:
            self.functions = []
        self.ifs = []
        self.loops = []
        self.switchis = []

        self.annotations = {}

    def filename(self, location):
        filename = location.file.name
        if filename not in self.annotations:
            with open(filename, "rb") as f:
                content = f.read()
            self.annotations[filename] = {"content": content}
            self.annotations[filename][0] = b'#include "cflow_inst.h"\n'
        return filename

    def add_annotation(self, annotation, location, add_offset=0):
        offset = location.offset + add_offset
        filename = self.filename(location)
        if offset not in self.annotations[filename]:
            self.annotations[filename][offset] = b""
        self.annotations[filename][offset] += annotation

    def prepent_annotation(self, annotation, location, add_offset=0):
        offset = location.offset + add_offset
        filename = self.filename(location)
        if offset not in self.annotations[filename]:
            self.annotations[filename][offset] = annotation
        else:
            self.annotations[filename][offset] = annotation + self.annotations[filename][offset]

    def visit_function(self, node):
        body = None
        for child in node.get_children():
            if (child.kind == CursorKind.COMPOUND_STMT):
                body = child
        if not body:
            return
        func_num = len(self.functions)
        self.functions.append({"num": func_num,
                               "file": self.filename(node.extent.start),
                               "name": node.spelling,
                               "line": node.extent.start.line,
                               "offset": node.extent.start.offset,
                               "end": node.extent.end.offset,
                               })
        if self.check_location(body.extent.start, [b"{"]) == False:
            print("Check location failed for function " + node.spelling)
            return
        self.add_annotation(b" _FUNC(" + bytes(str(func_num), "utf-8") + b") ", body.extent.start, 1)

        # special treatment for main function
        if node.spelling == "main":
            token_end = None
            for token in node.get_tokens():
                if token.spelling == "main":
                    token_end = token.extent.end
            self.add_annotation(b"_original", token_end)
            new_main = b'''

int main (int argc, char **argv) {
    _cflow_open("''' + bytes(filename, "utf-8") + b'''.trace.txt");
    int retval = main_original(argc, argv);
    _cflow_close();
    return retval;
}'''
            self.add_annotation(new_main, node.extent.end)

    def find_next_semi(self, location):
        filename = self.filename(location)
        content = self.annotations[filename]["content"]
        i = 0
        while (content[location.offset + i] not in b';'):
            i += 1
        return i

    def find_next_colon(self, location):
        filename = self.filename(location)
        content = self.annotations[filename]["content"]
        i = 0
        while (content[location.offset + i] not in b':'):
            i += 1
        return i

    def check_location(self, location, strlist):
        filename = self.filename(location)
        try:
            content = self.annotations[filename]["content"]
            offset = location.offset
            for s in strlist:
                if s == content[offset:offset+len(s)]:
                    return True
            return False
        except:
            return False

    def visit_if(self, node):
        self.ifs.append(node)
        if self.check_location(node.extent.start, [b"if"]) == False:
            print("Check location failed for if")
            return
        children = [c for c in node.get_children()]
        if_body = children[1]
        if len(children) == 3:
            else_body = children[2]
        else:
            else_body = None

        if else_body:
            if else_body.kind == CursorKind.COMPOUND_STMT:
                self.prepent_annotation(b" _ELSE ", else_body.extent.start, 1)
            else:
                self.prepent_annotation(b" { _ELSE ", else_body.extent.start)
                semi_off = self.find_next_semi(else_body.extent.end)
                self.prepent_annotation(b" }", else_body.extent.end, semi_off + 1)

        if if_body.kind == CursorKind.COMPOUND_STMT:
            self.prepent_annotation(b" _IF ", if_body.extent.start, 1)
            if not else_body:
                self.prepent_annotation(b" else { _ELSE }", node.extent.end)
        else:
            self.prepent_annotation(b" { _IF ", if_body.extent.start)
            semi_off = self.find_next_semi(if_body.extent.end)
            if else_body:
                self.prepent_annotation(b" }", if_body.extent.end, semi_off + 1)
            else:
                self.prepent_annotation(b" } else { _ELSE }", if_body.extent.end, semi_off + 1)

    def visit_loop(self, node):
        loop_id = bytes(str(len(self.loops)), "utf-8")
        self.loops.append(node)
        if self.check_location(node.extent.start, [b"for", b"while", b"do"]) == False:
            print("Check location failed for loop")
            return
        body = None
        for child in node.get_children():
            if (child.kind == CursorKind.COMPOUND_STMT):
                body = child
        self.add_annotation(b" _LOOP_START(" + loop_id + b") ", node.extent.start)
        if body:
            self.prepent_annotation(b" _LOOP_BODY(" + loop_id + b") ", body.extent.start, 1)
            self.prepent_annotation(b" _LOOP_END(" + loop_id + b")", node.extent.end)
        else:
            stmt = [c for c in node.get_children()][-1]
            self.prepent_annotation(b" { _LOOP_BODY(" + loop_id + b") ", stmt.extent.start)
            semi_off = self.find_next_semi(stmt.extent.end)
            self.prepent_annotation(b" } _LOOP_END(" + loop_id + b")", stmt.extent.end, semi_off + 1)
        # handle returns & gotos
        for descendant in node.walk_preorder():
            if (descendant.kind in (CursorKind.RETURN_STMT, CursorKind.GOTO_STMT)):
                self.add_annotation(b"_LOOP_END(" + loop_id + b") ", descendant.extent.start)

    def traverse_switch(self, node, switch_id):
        if (node.kind in (CursorKind.CASE_STMT, CursorKind.DEFAULT_STMT)):
            case_id = bytes(str(self.switch_case_count), "utf-8")
            number_end = [c for c in node.get_children()][0].extent.end
            try:
                colon_off = self.find_next_colon(number_end)
                self.add_annotation(b" _CASE(" + case_id + b", " + switch_id + b") ", number_end, colon_off+1)
            except IndexError:
                print(b"Failed to annotate _CASE(" + case_id + b", " + switch_id + b") ")
            self.switch_case_count += 1

        for child in node.get_children():
            if (child.kind != CursorKind.SWITCH_STMT):
                self.traverse_switch(child, switch_id)

    def visit_switch(self, node):
        switch_id = bytes(str(len(self.switchis)), "utf-8")
        self.switchis.append(node)
        if self.check_location(node.extent.start, [b"switch"]) == False:
            print("Check location failed for switch")
            return
        self.add_annotation(b" _SWITCH_START(" + switch_id + b") ", node.extent.start)
        self.switch_case_count = 0
        self.traverse_switch(node, switch_id)

    def annotate_all(self, filename):
        if filename in self.annotations:
            annotation = self.annotations[filename]
            content = annotation["content"]
            # overwrite
            if (b'#include "cflow_inst.h"' in content):
                print("Skipping " + filename + " (already annotated)")
                return False
            print("Overwriting " + filename + "...")
            prevchar = b' '
            with open(filename, "wb") as f:
                for offset, char_int in enumerate(content):
                    char = char_int.to_bytes(1, "little")
                    if offset in annotation:
                        ann = annotation[offset]
                        try:
                          if prevchar in b' \t\n' and ann[0] in b' ':
                            # skip the first ' ' because there already is a ws
                            ann = ann[1:]
                          if char in b' \t\n' and ann[-1] in b' ':
                            # skip the last ' ' because there already is a ws
                            ann = ann[:-1]
                        except TypeError:
                            print(char,prevchar,ann)
                        f.write(ann)
                    f.write(char)
                    prevchar = char
            return True
        else:
            print("Skipping " + filename + " (nothing to annotate)")
            return False

    def traverse(self, node):
        try:
            if (node.kind == CursorKind.FUNCTION_DECL):
                self.visit_function(node)
            elif (node.kind == CursorKind.IF_STMT):
                self.visit_if(node)
            elif (node.kind in (CursorKind.WHILE_STMT, CursorKind.FOR_STMT, CursorKind.DO_STMT)):
                self.visit_loop(node)
            elif (node.kind == CursorKind.SWITCH_STMT):
                self.visit_switch(node)
            elif (node.kind == CursorKind.GOTO_STMT):
                print("Limited support for goto. Check that the goto target is not inside a block!")
        except:
            print("Failed to annotate a " + str(node.kind))

        for child in node.get_children():
            self.traverse(child)


if __name__ == '__main__':
    import json
    filename = sys.argv[1]

    index = Index.create()
    tu = index.parse(filename)

    root = tu.cursor

    try:
        # We don't want to overwrite existing func_nums...
        with open("cflow_functions.json") as f:
            print("Reading cflow_functions.json")
            functions = json.load(f)
    except FileNotFoundError:
        print("Creating cflow_functions.json")
        functions = []

    instrumenter = Instrumenter(functions)
    instrumenter.traverse(root)
    annotated = instrumenter.annotate_all(filename)
    if (annotated):
        with open("cflow_functions.json", "w") as f:
            print("Writing cflow_functions.json")
            json.dump(instrumenter.functions, f, indent=2)
