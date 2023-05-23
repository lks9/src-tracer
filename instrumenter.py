#!/usr/bin/env python3

import os
import sqlite3
import argparse

from src_tracer.instrumenter import Instrumenter

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
ap.add_argument("--inline", action='store_true',
                help="instrument inline function calls and returns")
ap.add_argument("--no-main", action='store_true',
                help="do not instrument the main function to start tracing")
ap.add_argument("--anon", action='store_true',
                help="instrument all functions without a number")
ap.add_argument("--no-functions", action='store_true',
                help="do not instrument functions at all")
args = ap.parse_args()

# trace store dir
if args.store_dir:
    store_dir = args.store_dir
else:
    store_dir = os.path.dirname(args.filename)

# create connection to database
if args.database is None:
    database = os.path.join(store_dir, 'cflow_functions.db')
else:
    database = args.database
try:
    connection = sqlite3.connect(database)
except sqlite3.OperationalError:
    error = "the given path is not correct, make sure the dir exists beforehand"
    raise Exception(error)

# do the instrumentation
instrumenter = Instrumenter(connection, store_dir, case_instrument=args.cases, boolop_instrument=args.short_circuit,
                            return_instrument=not args.no_return, inline_instrument=args.inline,
                            main_instrument=not args.no_main, anon_instrument=args.anon,
                            function_instrument=not args.no_functions)
instrumenter.parse(args.filename)
instrumenter.annotate_all(args.filename)
