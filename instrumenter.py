#!/usr/bin/env python3

import os
import sqlite3
import argparse

from src_tracer.instrumenter import Instrumenter
from src_tracer.database import Database

# arguments
ap = argparse.ArgumentParser()
ap.add_argument("filename",
                help="Pre-preccessed C or C++ file to instrument.")
ap.add_argument("store_dir", nargs='?',
                help="Where to store database and traces.")
ap.add_argument("--database",
                help="Custom database path.")
ap.add_argument("--no-return", action='store_true',
                help="Do not instrument returns.")
ap.add_argument("--switch-number", action='store_true',
                help="Instrument to record switch number instead of case based bit-tracing.")
ap.add_argument("--short-circuit", action='store_true',
                help="Instrument short circuit operators.")
ap.add_argument("--short-circuit-full", action='store_true',
                help="Instrument almost all short circuit operators, even if unnecessary (implies --short-circuit).")
ap.add_argument("--no-inner", action='store_true',
                help="Do not instrument any control structrure including if, else, while, for.")
ap.add_argument("--inline", action='store_true',
                help="Instrument inline function calls and returns.")
ap.add_argument("--no-main", action='store_true',
                help="Do not instrument the main function to start trace recording.")
ap.add_argument("--record",
                help="Start trace recording in other function than main (implies --no-main).")
ap.add_argument("--no-close", action='store_true',
                help="Do not stop trace recording in main (or other) function.")
ap.add_argument("--anon", action='store_true',
                help="Instrument all functions without a number.")
ap.add_argument("--no-functions", action='store_true',
                help="Do not instrument functions at all.")
ap.add_argument("--no-calls", action='store_true',
                help="Do not instrument any calls. "
                "Currently we instrument exit() and friends, fork() and setjmp().")
ap.add_argument("--pointer-calls", action='store_true',
                help="Instrument pointer calls. "
                "Note that you have to compile your sources with -D_TRACE_POINTER_CALLS_ONLY to make use of it!")
ap.add_argument("--full", action='store_true',
                help="Instrument everything. Implies positive arguments above.")
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

case_instrument = not args.switch_number
boolop_instrument = args.full or args.short_circuit or args.short_circuit_full
boolop_full_instrument = args.full or args.short_circuit_full
return_instrument = not args.no_return
inline_instrument = args.full or args.inline
main_close = not args.no_close
anon_instrument = args.anon
function_instrument = not args.no_functions
inner_instrument = not args.no_inner
call_instrument = not args.no_calls
pointer_call_instrument = args.full or args.pointer_calls

# do the instrumentation
instrumenter = Instrumenter(database, store_dir, case_instrument=case_instrument,
                            boolop_instrument=boolop_instrument, boolop_full_instrument=boolop_full_instrument,
                            return_instrument=return_instrument, inline_instrument=inline_instrument,
                            main_instrument=main_instrument, main_spelling=main_spelling, main_close=main_close,
                            anon_instrument=anon_instrument,
                            function_instrument=function_instrument, inner_instrument=inner_instrument,
                            call_instrument=call_instrument, pointer_call_instrument=pointer_call_instrument)
instrumenter.parse(args.filename)
instrumenter.annotate_all(args.filename)
database.close_connection()
