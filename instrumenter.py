#!/usr/bin/env python3

import sys

from clang.cindex import Index, CursorKind

functions = []
ifs = []
loops = []
switchis = []

annotations = {}

def add_annotation(annotation, location, add_offset=0):
    offset = location.offset + add_offset
    filename = location.file.name
    if filename not in annotations:
        annotations[filename] = {}
        annotations[filename][0] = '#include "cflow_inst.h"\n'
    if offset not in annotations[filename]:
        annotations[filename][offset] = ""
    annotations[filename][offset] += annotation

def prepent_annotation(annotation, location, add_offset=0):
    offset = location.offset + add_offset
    filename = location.file.name
    if filename not in annotations:
        annotations[filename] = {}
        annotations[filename][0] = '#include "cflow_inst.h"\n'
    if offset not in annotations[filename]:
        annotations[filename][offset] = annotation
    else:
        annotations[filename][offset] = annotation + annotations[filename][offset]

def visit_function(node):
    body = None
    for child in node.get_children():
        if (child.kind == CursorKind.COMPOUND_STMT):
            body = child
    if not body:
        return
    func_num = str(len(functions))
    add_annotation(" _FUNC(" + func_num + ") ", body.extent.start, 1)
    functions.append(node)

    # special treatment for main function
    if node.spelling == "main":
        token_end = None
        for token in node.get_tokens():
            if token.spelling == "main":
                token_end = token.extent.end
        add_annotation("_original", token_end)
        new_main = '''

int main (int argc, char **argv) {
    _cflow_open("''' + filename + '''.trace.txt");
    int retval = main_original(argc, argv);
    _cflow_close();
    return retval;
}'''
        add_annotation(new_main, node.extent.end)

def visit_if(node):
    ifs.append(node)
    if_body = None
    else_body = None
    for child in node.get_children():
        if (child.kind == CursorKind.COMPOUND_STMT):
            if if_body:
                else_body = child
            else:
                if_body = child
    if else_body:
        prepent_annotation(" _ELSE ", else_body.extent.start, 1)
    else:
        prepent_annotation(" else { _ELSE }", node.extent.end)
    if if_body:
        prepent_annotation(" _IF ", if_body.extent.start, 1)
    else:
        stmt = [c for c in node.get_children()][-1]
        prepent_annotation(" { _IF ", stmt.extent.start)
        prepent_annotation("; }", stmt.extent.end)
    ifs.append(node)

def visit_loop(node):
    body = None
    for child in node.get_children():
        if (child.kind == CursorKind.COMPOUND_STMT):
            body = child
    loop_id = str(len(loops))
    add_annotation(" _LOOP_START(" + loop_id + ") ", node.extent.start)
    prepent_annotation(" _LOOP_END(" + loop_id + ")", node.extent.end)
    if body:
        prepent_annotation(" _LOOP_BODY(" + loop_id + ") ", body.extent.start, 1)
    else:
        stmt = [c for c in node.get_children()][-1]
        prepent_annotation(" { _LOOP_BODY(" + loop_id + ") ", stmt.extent.start)
        prepent_annotation("; }", stmt.extent.end)
    # handle returns
    for descendant in node.walk_preorder():
        if (descendant.kind == CursorKind.RETURN_STMT):
            add_annotation("_LOOP_END(" + loop_id + ") ", descendant.extent.start)
    loops.append(node)


def traverse_switch(node, switch_id):
    global switch_case_count
    if (node.kind in (CursorKind.CASE_STMT, CursorKind.DEFAULT_STMT)):
        stmt = [c for c in node.get_children()][-1]
        add_annotation(" _CASE(" + str(switch_case_count) + ", " + switch_id + ") ", stmt.extent.start)
        switch_case_count += 1

    for child in node.get_children():
        if (child.kind != CursorKind.SWITCH_STMT):
            traverse_switch(child, switch_id)

def visit_switch(node):
    global switch_case_count
    switch_id = str(len(switchis))
    add_annotation(" _SWITCH_START(" + switch_id + ") ", node.extent.start)
    switch_case_count = 0
    traverse_switch(node, switch_id)
    switchis.append(node)

def annotate_all():
    for filename, annotation in annotations.items():
        with open(filename) as f:
            content = f.read()
        # overwrite
        if ('#include "cflow_file.h"' in content):
            print("Skipping " + filename + " (already annotated)")
            continue
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


def traverse(node):
    if (node.kind == CursorKind.FUNCTION_DECL):
        visit_function(node)
    elif (node.kind == CursorKind.IF_STMT):
        visit_if(node)
    elif (node.kind in (CursorKind.WHILE_STMT, CursorKind.FOR_STMT, CursorKind.DO_STMT)):
        visit_loop(node)
    elif (node.kind == CursorKind.SWITCH_STMT):
        visit_switch(node)
    elif (node.kind == CursorKind.GOTO_STMT):
        raise Exception("goto is not supported. Please refactor or do the instrumentation manually.")

    for child in node.get_children():
        traverse(child)

if __name__ == '__main__':
    filename = sys.argv[1]

    index = Index.create()
    tu = index.parse(filename)

    root = tu.cursor

    traverse(root)

    annotate_all()
