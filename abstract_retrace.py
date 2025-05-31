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
ap_out = ap.add_argument_group('output options')
ap_out.add_argument("--lines", action='store_true', default=False,
                    help="Output the lines (default)")
ap_out.add_argument("--cbmc", action='store_true', default=False,
                    help="Output a control flow trace for CBMC's new --retrace option")
ap_out.add_argument("--cbmc-trace-only", action='store_true', default=False,
                    help="Bare CBMC control flow trace without command to run")
ap_instru = ap.add_argument_group('instrumentation options')
ap_instru.add_argument("--returns", action='store_true', default=False,
                       help="Instrument returns (default off).")
args = ap.parse_args()

output_format="lines"

if args.lines:
    output_format="lines"
elif args.cbmc or args.cbmc_trace_only:
    output_format="cbmc"

if args.cbmc_trace_only:
    silent=True
else:
    silent=False

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

retracer = Line_Retracer(database, return_instrument=return_instrument, output_format=output_format, silent=silent)

retracer.abstract_retrace(iter(trace))

if database:
    database.close_connection()
