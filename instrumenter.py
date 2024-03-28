#!/usr/bin/env python3

import os
import sqlite3
import argparse

from src_tracer.instrumenter import Instrumenter
from src_tracer.database import Database

# arguments
ap = argparse.ArgumentParser()
ap.add_argument("filename",
                help="pre-preccessed C or C++ file to instrument")
ap.add_argument("store_dir", nargs='?',
                help="where to store database and traces")
ap.add_argument("--database",
                help="custom database path")
ap.add_argument("--no-return", action='store_true',
                help="do not instrument returns")
ap.add_argument("--cases", action='store_true',
                help="instrument all switch cases instead of switch number (experimental)")
ap.add_argument("--short-circuit", action='store_true',
                help="instrument short circuit operators (experimental)")
ap.add_argument("--no-inner", action='store_true',
                help="do not instrument any control structrure including if, else, while, for")
ap.add_argument("--inline", action='store_true',
                help="instrument inline function calls and returns")
ap.add_argument("--no-main", action='store_true',
                help="do not instrument the main function to start trace recording")
ap.add_argument("--record",
                help="start trace recording in other function than main (implies --no-main)")
ap.add_argument("--close", action='store_true',
                help="stop trace recording in main (or other) function")
ap.add_argument("--anon", action='store_true',
                help="instrument all functions without a number")
ap.add_argument("--no-functions", action='store_true',
                help="do not instrument functions at all")
ap.add_argument("--no-calls", action='store_true',
                help="do not instrument any calls, currently we instrument only fork() and setjmp()")
args = ap.parse_args()

# trace store dir
if args.store_dir:
    store_dir = args.store_dir
else:
    store_dir = os.path.dirname(args.filename)

# create connection to database
try:
    if args.database is None:
        database = Database(store_dir)
    else:
        database = Database(store_dir=None, path=args.database)
except sqlite3.OperationalError:
    error = "the given path is not correct, make sure the dir exists beforehand"
    raise Exception(error)

# custom trace recording start?
main_instrument = not args.no_main
main_spelling = "main"
if args.record:
    main_instrument = True
    main_spelling = args.record

# do the instrumentation
instrumenter = Instrumenter(database, store_dir, case_instrument=args.cases, boolop_instrument=args.short_circuit,
                            return_instrument=not args.no_return, inline_instrument=args.inline,
                            main_instrument=main_instrument, main_spelling=main_spelling, main_close=args.close,
                            anon_instrument=args.anon,
                            function_instrument=not args.no_functions, inner_instrument=not args.no_inner,
                            call_instrument=not args.no_calls)
instrumenter.parse(args.filename)
instrumenter.annotate_all(args.filename)
database.close_connection()
