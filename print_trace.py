#!/usr/bin/env python3

INDENT_WITH = "| "
COUNT_MAX = 75

import sys
import os
import sqlite3
import argparse

from src_tracer.trace import Trace
from src_tracer.util import Util

# arguments
ap = argparse.ArgumentParser()
ap.add_argument("trace_file",
                help="file containing the trace")
ap.add_argument("--seek", type=int, default=0,
                help="skip bytes in the beginning of the tracefile")
ap.add_argument("--count", type=int, default=-1,
                help="stop after reading count bytes from the trace")
ap.add_argument("--database",
                help="path to the function database")
args = ap.parse_args()

# create connection to database
if args.database is None:
    database_path = os.path.dirname(args.trace_file)
    database = os.path.join(database_path, 'cflow_functions.db')
else:
    database = args.database
if os.path.exists(database):
    connection = sqlite3.connect(database)
    cursor = connection.cursor()
else:
    cursor = None

trace = Trace.from_file(args.trace_file, seek_bytes=args.seek, count_bytes=args.count)

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

for elem in trace:
    if elem.letter == 'R':
        indent -= 1
        print_extra('R')
    elif elem.bs == b'':
        print_with_count(f"{elem.letter}")
    else:
        num = int.from_bytes(elem.bs, "little")
        if elem.letter == 'F':
            name = Util.get_name(cursor, num)
            if name is not None:
                # All upper case letters in the trace are treated as elem,
                # so we have to print name.lower() instead of name
                print_extra(f"{elem.letter}{num:x} {name.lower()}")
            else:
                print_extra(f"{elem.letter}{num:x}")
            indent += 1
        else:
            print_extra(f"{elem.letter}{num:x}")

if not previous_newline:
    print_newline()
