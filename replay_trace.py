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

# silence some loggers for angr's sub-classes:
logging.getLogger("cle.loader").setLevel(logging.CRITICAL)
logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.CRITICAL)
logging.getLogger("angr.engines.successors").setLevel(logging.CRITICAL)

# set debug level for retracing
logging.getLogger("src_tracer.retrace").setLevel(logging.DEBUG)

# arguments
ap = argparse.ArgumentParser()
ap.add_argument("binary_name",
                help="name of the retrace binary")
ap.add_argument("trace_file",
                help="file containing the trace")
ap.add_argument("--seek", type=int, default=0,
                help="skip bytes in the beginning of the tracefile")
ap.add_argument("--count", type=int, default=-1,
                help="stop after reading count bytes from the trace")
ap.add_argument("--assertions", action='store_true',
                help="print assertion check results after retracing finished")
arggroup = ap.add_mutually_exclusive_group()
arggroup.add_argument("--database",
                      help="path to the function database")
arggroup.add_argument("--fname",
                      help="don't use the database and start tracing with function fname")
args = ap.parse_args()

# create connection to database
if args.fname is None:
    if args.database is None:
        database_path = os.path.dirname(args.trace_file)
        database = os.path.join(database_path, 'cflow_functions.db')
    else:
        database = args.database
    try:
        connection = sqlite3.connect(database)
    except sqlite3.OperationalError:
        error = f"Could not open database from {database}"
        raise Exception(error)
    cursor = connection.cursor()
else:
    cursor = None

# retracing
trace = Trace.from_file(args.trace_file, seek_bytes=args.seek, count_bytes=args.count)

source_tracer = SourceTraceReplayer(args.binary_name, auto_load_libs=False)
(simgr, state) = source_tracer.follow_trace(trace, args.fname, cursor)

# assertion checks
if args.assertions:
    res = source_tracer.check_all_assertions(state)
    print()
    print(f"Final assertion check result: {res.name}")
    print()
