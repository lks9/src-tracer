#!/usr/bin/env python3

import sys

from clang.cindex import Index, CursorKind


class Instrumenter:

    def __init__(self):
        self.functions = []
        self.ifs = []
        self.loops = []
        self.switchis = []

        self.annotations = {}

    def add_annotation(self, annotation, location, add_offset=0):
        offset = location.offset + add_offset
        filename = location.file.name
        if filename not in self.annotations:
            self.annotations[filename] = {}
            self.annotations[filename][0] = '#include "cflow_inst.h"\n'
        if offset not in self.annotations[filename]:
            self.annotations[filename][offset] = ""
        self.annotations[filename][offset] += annotation

    def prepent_annotation(self, annotation, location, add_offset=0):
        offset = location.offset + add_offset
        filename = location.file.name
        if filename not in self.annotations:
            self.annotations[filename] = {}
            self.annotations[filename][0] = '#include "cflow_inst.h"\n'
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
        func_num = str(len(self.functions))
        self.add_annotation(" _FUNC(" + func_num + ") ", body.extent.start, 1)
        self.functions.append(node)

        # special treatment for main function
        if node.spelling == "main":
            token_end = None
            for token in node.get_tokens():
                if token.spelling == "main":
                    token_end = token.extent.end
            self.add_annotation("_original", token_end)
            new_main = '''

int main (int argc, char **argv) {
    _cflow_open("''' + filename + '''.trace.txt");
    int retval = main_original(argc, argv);
    _cflow_close();
    return retval;
}'''
            self.add_annotation(new_main, node.extent.end)

    def visit_if(self, node):
        self.ifs.append(node)
        if_body = None
        else_body = None
        for child in node.get_children():
            if (child.kind == CursorKind.COMPOUND_STMT):
                if if_body:
                    else_body = child
                else:
                    if_body = child
        if else_body:
            self.prepent_annotation(" _ELSE ", else_body.extent.start, 1)
        else:
            self.prepent_annotation(" else { _ELSE }", node.extent.end)
        if if_body:
            self.prepent_annotation(" _IF ", if_body.extent.start, 1)
        else:
            stmt = [c for c in node.get_children()][-1]
            self.prepent_annotation(" { _IF ", stmt.extent.start)
            self.prepent_annotation("; }", stmt.extent.end)
        self.ifs.append(node)

    def visit_loop(self, node):
        body = None
        for child in node.get_children():
            if (child.kind == CursorKind.COMPOUND_STMT):
                body = child
        loop_id = str(len(self.loops))
        self.add_annotation(" _LOOP_START(" + loop_id + ") ", node.extent.start)
        self.prepent_annotation(" _LOOP_END(" + loop_id + ")", node.extent.end)
        if body:
            self.prepent_annotation(" _LOOP_BODY(" + loop_id + ") ", body.extent.start, 1)
        else:
            stmt = [c for c in node.get_children()][-1]
            self.prepent_annotation(" { _LOOP_BODY(" + loop_id + ") ", stmt.extent.start)
            self.prepent_annotation("; }", stmt.extent.end)
        # handle returns
        for descendant in node.walk_preorder():
            if (descendant.kind == CursorKind.RETURN_STMT):
                self.add_annotation("_LOOP_END(" + loop_id + ") ", descendant.extent.start)
        self.loops.append(node)

    def traverse_switch(self, node, switch_id):
        if (node.kind in (CursorKind.CASE_STMT, CursorKind.DEFAULT_STMT)):
            stmt = [c for c in node.get_children()][-1]
            self.add_annotation(" _CASE(" + str(self.switch_case_count) + ", " + switch_id + ") ", stmt.extent.start)
            self.switch_case_count += 1

        for child in node.get_children():
            if (child.kind != CursorKind.SWITCH_STMT):
                self.traverse_switch(child, switch_id)

    def visit_switch(self, node):
        switch_id = str(len(self.switchis))
        self.add_annotation(" _SWITCH_START(" + switch_id + ") ", node.extent.start)
        self.switch_case_count = 0
        self.traverse_switch(node, switch_id)
        self.switchis.append(node)

    def annotate_all(self, filename):
        if filename in self.annotations:
            annotation = self.annotations[filename]
            with open(filename) as f:
                content = f.read()
            # overwrite
            if ('#include "cflow_file.h"' in content):
                print("Skipping " + filename + " (already annotated)")
                return
            print("Overwriting " + filename + "...")
            prevchar = ' '
            with open(filename, "w") as f:
                for offset, char in enumerate(content):
                    if offset in annotation:
                        ann = annotation[offset]
                        if prevchar in (' ', '\t', '\n') and ann[0] == ' ':
                            # skip the first ' ' because there already is a ws
                            ann = ann[1:]
                        if char in (' ', '\t', '\n') and ann[-1] == ' ':
                            # skip the last ' ' because there already is a ws
                            ann = ann[:-1]
                        f.write(ann)
                    f.write(char)
                    prevchar = char
        else:
            print("Skipping " + filename + " (nothing to annotate)")

    def traverse(self, node):
        if (node.kind == CursorKind.FUNCTION_DECL):
            self.visit_function(node)
        elif (node.kind == CursorKind.IF_STMT):
            self.visit_if(node)
        elif (node.kind in (CursorKind.WHILE_STMT, CursorKind.FOR_STMT, CursorKind.DO_STMT)):
            self.visit_loop(node)
        elif (node.kind == CursorKind.SWITCH_STMT):
            self.visit_switch(node)
        elif (node.kind == CursorKind.GOTO_STMT):
            raise Exception("goto is not supported. Please refactor or do the instrumentation manually.")

        for child in node.get_children():
            self.traverse(child)


if __name__ == '__main__':
    filename = sys.argv[1]

    index = Index.create()
    tu = index.parse(filename)

    root = tu.cursor

    instrumenter = Instrumenter()
    instrumenter.traverse(root)
    instrumenter.annotate_all(filename)
