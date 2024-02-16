#!/usr/bin/env python3

COUNT_MAX = 75

import sys
import os
import argparse

from src_tracer.trace import Trace


# arguments
ap = argparse.ArgumentParser()
ap.add_argument("trace_file",
                help="file containing the trace")
ap.add_argument("-o", "--out",
                help="output file (default: print to terminal)")
ap.add_argument("--seek", type=int, default=0,
                help="skip bytes in the beginning of the tracefile")
ap.add_argument("--count", type=int, default=-1,
                help="read count bytes from the trace (default: read all)")
ap.add_argument("--count-elems", metavar="ELEMS", type=int, default=1,
                help="read extra elems after count (default: 1)")
args = ap.parse_args()

# input
trace = Trace.from_file(args.trace_file, seek_bytes=args.seek, count_bytes=args.count, count_elems=args.count_elems)

# output
if args.out:
    out = open(args.out, 'w')
else:
    out = None

print("#include <assert.h>", file=out)
print("#include <stdbool.h>", file=out)
print("", file=out)
print("#include <src_tracer/retrace.h>", file=out)
print("struct retrace_elem retrace_arr [RETRACE_ARR_LEN_MAX] = {", file=out)
retrace_arr_len = 0
for elem in trace:
    print(f"    {{'{elem.letter}', {elem.num} }},", file=out)
    retrace_arr_len += 1
print("};", file=out)
print(f"int retrace_arr_len = {retrace_arr_len};", file=out)
print("int retrace_i = 0;", file=out)
print("", file=out)
print("char *_retrace_assert_names[ASSERT_BUF_SIZE];", file=out)
print("bool _retrace_asserts[ASSERT_BUF_SIZE];", file=out)
print("int _retrace_assert_idx;", file=out)
