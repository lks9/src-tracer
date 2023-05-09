#!/usr/bin/env python3

import logging
import sys
import sqlite3
import os
import argparse

from src_tracer.retrace import SourceTraceReplayer
from src_tracer.trace import Trace

# better hex printing
try:
    import monkeyhex
except ModuleNotFoundError:
    pass

# set debug level for retracing
logging.getLogger("src_tracer.retrace").setLevel(logging.DEBUG)

# arguments
ap = argparse.ArgumentParser()
ap.add_argument("binary_name",
                help="name of the retrace binary")
ap.add_argument("trace_file",
                help="file containing the trace")
ap.add_argument("--seek", type=int, default=0, metavar="N",
                help="skip N bytes in the beginning of the tracefile")
ap.add_argument("--count", type=int, default=-1, metavar="N",
                help="read N bytes from the trace (default: read all)")
ap.add_argument("--count-elems", type=int, default=1, metavar="N",
                help="read N elems extra after count (default: 1)")
ap.add_argument("--assertions", action='store_true',
                help="print assertion check results after retracing finished")
arggroup = ap.add_mutually_exclusive_group()
arggroup.add_argument("--database",
                      help="path to the function database")
arggroup.add_argument("--fname",
                      help="don't use the database and start tracing with function fname")
ap.add_argument("--add-options", nargs="*", default=[],
                help="list of angr state options to add")
ap.add_argument("--remove-options", nargs="*", default=[],
                help="list of angr state options to remove")
group2 = ap.add_mutually_exclusive_group()
group2.add_argument("--merge", type=int, metavar="N",
                    help="merge states after reading N elements with multiple found")
group2.add_argument("--drop", type=int, metavar="N",
                    help="merge states after reading N elements with multiple found")
args = ap.parse_args()

# create connection to database
if args.fname is None:
    if args.database is None:
        database_path = os.path.dirname(args.trace_file)
        database = os.path.join(database_path, 'cflow_functions.db')
    else:
        database = args.database
    if not os.path.exists(database):
        error = f"Could not open database from {database}, try --fname or --database"
        raise Exception(error)
    connection = sqlite3.connect(database)
    cursor = connection.cursor()
else:
    cursor = None

# retracing

# options
DEFAULT_ADD_OPS = {"COPY_STATES",
                   "ANY_FILE_MIGHT_EXIST",
                   "SYMBOL_FILL_UNCONSTRAINED_MEMORY",
                   "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"}
DEFAULT_REMOVE_OPS = {"ALL_FILES_EXIST"}

# Some useful options:
#   CONSERVATIVE_READ_STRATEGY, CONSERVATIVE_WRITE_STRATEGY (for more reliable retracing)
#   AVOID_MULTIVALUED_READS AVOID_MULTIVALUED_WRITES plus --merge 1 (for fast retracing, angr "fastpath" mode)
#   BYPASS_UNSUPPORTED_... (retrace even when unsupported in angr)
#   remove COPY_STATES
#   SIMPLIFY_... (might change performance)
#   ...

add = set(args.add_options)
remove = set(args.remove_options)

from_def_add = DEFAULT_ADD_OPS.difference(remove)
from_def_rem = DEFAULT_REMOVE_OPS.difference(add)
add.update(from_def_add)
remove.update(from_def_rem)

# merging
merging = False
dropping = False
merge_after = None
if args.merge is not None:
    merging = True
    merge_after = args.merge
elif args.drop is not None:
    dropping = True
    merge_after = args.drop

trace = Trace.from_file(args.trace_file, seek_bytes=args.seek, count_bytes=args.count, count_elems=args.count_elems)
source_tracer = SourceTraceReplayer(args.binary_name, auto_load_libs=False)
(simgr, state) = source_tracer.follow_trace(trace, args.fname, cursor, add_options=add, remove_options=remove,
                                            merging=merging, dropping=dropping, merge_after=merge_after)

# assertion checks
if args.assertions:
    res = source_tracer.check_all_assertions(state)
    print()
    print(f"Final assertion check result: {res.name}")
    print()
