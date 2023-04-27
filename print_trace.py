#!/usr/bin/env python3

INDENT_WITH = "| "
COUNT_MAX = 75

import sys
import os
import sqlite3

from src_tracer.trace import Trace
from src_tracer.util import Util


if len(sys.argv) == 2:
    filename = sys.argv[1]
    database_path = ""
elif len(sys.argv) == 3:
    filename = sys.argv[1]
    database_path = sys.argv[2]
else:
    usage = f"Usage: python3 {sys.argv[0]} <tracefile> <func_database_dir_path>"
    raise Exception(usage)

# create connection to database
try:
    connection = sqlite3.connect(os.path.join(database_path, 'cflow_functions.db'))
except sqlite3.OperationalError:
    error = "the given path is not correct, make sure the dir exists beforehand"
    raise Exception(error)

trace = Trace.from_file(filename)

cursor = connection.cursor()

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
            name = Util.get_name(cursor, num)
            if name is not None:
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
