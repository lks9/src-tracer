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
                help="read count bytes from the trace (default: read all)")
ap.add_argument("--count-elems", type=int, default=1,
                help="read extra elems after count (default: 1)")
ap.add_argument("--database",
                help="path to the function database")
ap.add_argument("--pretty", type=int, default=5,
    help="5: pretty (default), 5+4: indent, 5+3: function names, 1 compact, 0: no newline, -1: informative list")
ap.add_argument("--show-pos", action='store_true',
                help="for each element show its count offset in the trace")
args = ap.parse_args()

# create connection to database
if args.pretty in (5,3):
    if args.database is None:
        database_path = os.path.dirname(args.trace_file)
        database = os.path.join(database_path, 'cflow_functions.db')
    else:
        database = args.database
    if not os.path.exists(database):
        error = f"Could not open database from {database}, try --pretty 4 or --database"
        raise Exception(error)
    connection = sqlite3.connect(database)
    cursor = connection.cursor()
else:
    cursor = None

if args.pretty in (0,1) and args.show_pos:
    error = "--show_pos is only available for pretty > 1"
    raise Exception(error)

trace = Trace.from_file(args.trace_file, seek_bytes=args.seek, count_bytes=args.count, count_elems=args.count_elems)

previous_newline = True
indent = 0
count = 0

def print_indent():
    global previous_newline, indent, count, INDENT_WITH, COUNT_MAX
    if args.pretty == 1 and count < COUNT_MAX:
        previous_newline = False
        return
    if not previous_newline:
        print_newline()
    previous_newline = False
    if args.pretty < 4:
        return
    for i in range(indent):
        print(INDENT_WITH, end='')
    count = len(INDENT_WITH)*indent

def print_newline():
    global previous_newline, indent, count, INDENT_WITH, COUNT_MAX
    if args.pretty > 0:
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
    print_indent()
    print(s, end='')
    count += len(s)
    if args.pretty > 1:
        print_newline()

if args.pretty == -1:
    for elem in trace:
        print(elem)
    sys.exit()

for elem in trace:
    if elem.letter == 'R':
        indent -= 1
        print_extra(elem.pretty(show_pos=args.show_pos))
    elif elem.bs == b'':
        print_with_count(f"{elem.letter}")
    else:
        num = int.from_bytes(elem.bs, "little")
        if elem.letter == 'F':
            if args.pretty in (5,3):
                name = Util.get_name(cursor, num)
                # All upper case letters in the trace are treated as elem,
                # so we have to print name.lower() instead of name
                print_extra(elem.pretty(show_pos=args.show_pos, name=name.lower()))
            else:
                print_extra(elem.pretty(show_pos=args.show_pos))
            indent += 1
        else:
            print_extra(elem.pretty(show_pos=args.show_pos))

if not previous_newline:
    print_newline()
