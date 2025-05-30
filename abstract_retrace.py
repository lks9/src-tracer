#!/usr/bin/env python3

import sys
import os
import argparse

from src_tracer.trace import Trace
from src_tracer.database import Database
from src_tracer.abstract_retrace import Line_Retracer


# arguments
ap = argparse.ArgumentParser()
ap.add_argument("trace_file",
                help="file containing the trace")
ap_in = ap.add_argument_group('trace input options')
ap_in.add_argument("--seek", type=int, default=0,
                   help="skip bytes in the beginning of the tracefile")
ap_in.add_argument("--count", type=int, default=-1,
                   help="read count bytes from the trace (default: read all)")
ap_in.add_argument("--count-elems", metavar="ELEMS", type=int, default=1,
                   help="read extra elems after count (default: 1)")
ap_in.add_argument("--database",
                   help="path to the function database")
ap_instru = ap.add_argument_group('instrumentation options')
ap_instru.add_argument("--returns", action='store_true', default=False,
                       help="Instrument returns (default off).")
ap_out = ap.add_argument_group('output options')
ap_out.add_argument("--output-lines",
                    help="Output the lines (default)")
ap_out.add_argument("--output-cbmc",
                    help="Output a control flow trace for CBMC's new --retrace option")
args = ap.parse_args()


return_instrument = args.returns

# create connection to database
try:
    if args.database is None:
        database_dir = os.path.dirname(args.trace_file)
        database_path = os.path.join(database_dir, 'function_database.db')
    else:
        database_path = args.database
    if not os.path.exists(database_path):
        error = f"Could not open database from {database_path}, use --database"
        raise Exception(error)
    database = Database(store_dir=None, path=database_path)
except:
    database = None

trace = Trace.from_file(args.trace_file, seek_bytes=args.seek, count_bytes=args.count, count_elems=args.count_elems)

retracer = Line_Retracer(database, return_instrument=return_instrument)

retracer.abstract_retrace(iter(trace))

if database:
    database.close_connection()
