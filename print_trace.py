#!/usr/bin/env python3

INDENT_WITH = "| "
COUNT_MAX = 75

import sys

from src_tracer.trace import Trace

filename = sys.argv[1]

trace = Trace.from_file(filename)

try:
    import json
    with open("cflow_functions.json") as f:
        functions = json.load(f)
except:
    functions = None

previous_newline = True
indent = 0
count = 0

def print_indent():
    global previous_newline, indent, count, INDENT_WITH, COUNT_MAX
    if not previous_newline:
        print_newline()
    for i in range(indent):
        print(INDENT_WITH, end='')
    count = len(INDENT_WITH)*indent
    previous_newline = False

def print_newline():
    global previous_newline, indent, count, INDENT_WITH, COUNT_MAX
    print(end='\n')
    count = 0
    previous_newline = True

def print_with_count(s):
    global previous_newline, indent, count, INDENT_WITH, COUNT_MAX
    if previous_newline or count >= COUNT_MAX:
        print_indent()
    count += len(s)
    print(s, end='')

def print_extra(s):
    global previous_newline, indent, count, INDENT_WITH, COUNT_MAX
    if not previous_newline:
        print_newline()
    print_indent()
    print(s, end='')
    print_newline()

for (elem, bs) in trace:
    if elem == 'R':
        indent -= 1
        print_extra('R')
    elif bs == b'':
        print_with_count(f"{elem}")
    else:
        num = int.from_bytes(bs, "little")
        if elem == 'F':
            if functions:
                name = functions["hex_list"][num]["name"]
                # All upper case letters in the trace are treated as elem,
                # so we have to print name.lower() instead of name
                print_extra(f"{elem}{num:x} {name.lower()}")
            else:
                print_extra(f"{elem}{num:x}")
            indent += 1
        else:
            print_extra(f"{elem}{num:x}")

if not previous_newline:
    print_newline()
