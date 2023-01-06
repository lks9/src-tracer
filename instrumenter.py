#!/usr/bin/env python3

import sys

from clang.cindex import Index, CursorKind

functions = []
ifs = []
loops = []

annotations = {}

def visit_function(node):
    body = None
    for child in node.get_children():
        if (child.kind == CursorKind.COMPOUND_STMT):
            body = child
    if not body:
        return
    body_start = body.extent.start
    filename = body_start.file.name
    if filename not in annotations:
        annotations[filename] = {}
    func_num = str(len(functions))
    annotations[filename][body_start.offset + 1] = " _FUNC(" + func_num + ") "
    functions.append(node)

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
    if filename not in annotations:
        annotations[filename] = {}
    annotations[filename][if_start.offset + 1] = " _IF "
    annotations[filename][else_start.offset + 1] = " _ELSE "
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
    if filename not in annotations:
        annotations[filename] = {}
    loop_id = str(len(loops))
    annotations[filename][start.offset] = " _LOOP_START(" + loop_id + ") "
    annotations[filename][body_start.offset + 1] = " _LOOP_BODY(" + loop_id + ") "
    annotations[filename][end.offset] = " _LOOP_END(" + loop_id + ") "
    loops.append(node)

def annotate_all():
    for filename, annotation in annotations.items():
        with open(filename) as f:
            content = f.read()
        print("+++ " + filename + " +++")
        for offset, char in enumerate(content):
            if offset in annotation:
                sys.stdout.write(annotation[offset])
            sys.stdout.write(char)

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
