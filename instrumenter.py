#!/usr/bin/env python3

import sys

from clang.cindex import Index, CursorKind

functions = []
ifs = []
loops = []

annotations = {}

def add_annotation(annotation, filename, offset):
    if filename not in annotations:
        annotations[filename] = {}
        annotations[filename][0] = '#include "cflow_inst.h"\n'
    if offset not in annotations[filename]:
        annotations[filename][offset] = ""
    annotations[filename][offset] += annotation

def visit_function(node):
    body = None
    for child in node.get_children():
        if (child.kind == CursorKind.COMPOUND_STMT):
            body = child
    if not body:
        return
    body_start = body.extent.start
    filename = body_start.file.name
    func_num = str(len(functions))
    add_annotation(" _FUNC(" + func_num + ") ", filename, body_start.offset + 1)
    functions.append(node)

    # special treatment for main function
    if node.spelling == "main":
        token_end = None
        for token in node.get_tokens():
            if token.spelling == "main":
                token_end = token.extent.end.offset
        add_annotation("_original", filename, token_end)
        new_main = '''

int main (int argc, char **argv) {
    _cflow_open("''' + filename + '''.trace.txt");
    int retval = main_original(argc, argv);
    _cflow_close();
    return retval;
}'''
        add_annotation(new_main, filename, node.extent.end.offset)

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
    if_start = if_body.extent.start
    else_start = else_body.extent.start
    filename = if_start.file.name
    add_annotation(" _IF ", filename, if_start.offset + 1)
    add_annotation(" _ELSE ", filename, else_start.offset + 1)
    ifs.append(node)

def visit_loop(node):
    body = None
    for child in node.get_children():
        if (child.kind == CursorKind.COMPOUND_STMT):
            body = child
    if not body:
        return
    start = node.extent.start
    end = node.extent.end
    body_start = body.extent.start
    filename = start.file.name
    loop_id = str(len(loops))
    add_annotation(" _LOOP_START(" + loop_id + ") ", filename, start.offset)
    add_annotation(" _LOOP_BODY(" + loop_id + ") ", filename, body_start.offset + 1)
    add_annotation(" _LOOP_END(" + loop_id + ") ", filename, end.offset)
    loops.append(node)

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
    elif (node.kind in (CursorKind.WHILE_STMT, CursorKind.FOR_STMT)):
        visit_loop(node)

    for child in node.get_children():
        traverse(child)

if __name__ == '__main__':
    filename = sys.argv[1]

    index = Index.create()
    tu = index.parse(filename)

    root = tu.cursor

    traverse(root)

    annotate_all()
