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
ap.add_argument("--output",
                help="Output file (default same as input)")
ap_instru = ap.add_argument_group('instrumentation options')
ap_instru.add_argument("--returns", action='store_true', default=False,
                help="Instrument returns (default off).")
ap_instru.add_argument("--no-returns", action='store_false', dest='returns')
ap_instru.add_argument("--tailcall-returns", action='store_true', default=True,
                help="Assume that returns with function calls are all tailcalls (default). "
                "This makes recording more efficient!")
ap_instru.add_argument("--no-tailcall-returns", action='store_false', dest='tailcall_returns')
ap_instru.add_argument("--cases", action='store_true', default=True,
                help="Instrument each switch case for bit-tracing (default).")
ap_instru.add_argument("--switch-number", action='store_false', dest='cases',
                help="Instrument to trace switch number (default off; disables --cases).")
ap_instru.add_argument("--short-circuit", action='store_true', default=False,
                help="Instrument short circuit operators (default off).")
ap_instru.add_argument("--no-short-circuit", action='store_false', dest='short_circuit')
ap_instru.add_argument("--short-circuit-full", action='store_true', default=False,
                help="Instrument almost all short circuit operators, even if unnecessary (implies --short-circuit).")
ap_instru.add_argument("--inner", action='store_true', default=True,
                help="Instrument any control structrure including if, else, while, for (default).")
ap_instru.add_argument("--no-inner", action='store_false', dest='inner')
ap_instru.add_argument("--inline", action='store_true', default=False,
                help="Instrument inline function calls and returns (default off).")
ap_instru.add_argument("--no-inline", action='store_false', dest='inline')
ap_instru.add_argument("--trivial", action='store_true', default=False,
                help="Instrument trivial functions (default off).")
ap_instru.add_argument("--no-trivial", action='store_false', dest='trivial')
ap_instru.add_argument("--exclude", nargs='*',
                help="No instrumentation inside these functions")
ap_instru.add_argument("--main", action='store_true', default=True,
                help="Instrument the main function to start trace recording (default).")
ap_instru.add_argument("--no-main", action='store_false', dest='main')
ap_instru.add_argument("--record",
                help="Start trace recording in other function than main (implies --no-main).")
ap_instru.add_argument("--close", action='store_true', default=True,
                help="Stop trace recording when main (or other) function returns (default).")
ap_instru.add_argument("--no-close", action='store_false', dest='close')
ap_instru.add_argument("--functions", action='store_true', default=True,
                help="Instrument functions (default).")
ap_instru.add_argument("--no-functions", action='store_false', dest='functions')
ap_instru.add_argument("--anon", action='store_true', default=False,
                help="Instrument all functions without a number (default off).")
ap_instru.add_argument("--calls", action='store_true', default=True,
                help="Instrument some function calls. "
                "Currently we instrument exit() and friends, fork() and setjmp().")
ap_instru.add_argument("--no-calls", action='store_false', dest='calls')
ap_instru.add_argument("--pointer-calls", action='store_true', default=False,
                help="Instrument all function calls via pointers (default off). "
                "In effect, other function calls and returns wont be traced.")
ap.add_argument("--full", action='store_true',
                help="Instrument whatever possible. Implies most positive instrumentation options.")
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
main_instrument = args.main
main_spelling = "main"
if args.record:
    main_instrument = True
    main_spelling = args.record

case_instrument = args.full or args.cases
boolop_instrument = args.full or args.short_circuit or args.short_circuit_full
boolop_full_instrument = args.full or args.short_circuit_full
return_instrument = args.full or args.returns
assume_tailcall = not args.full and args.tailcall_returns
inline_instrument = args.full or args.inline
trivial_instrument = args.full or args.trivial
main_close = args.full or args.close
anon_instrument = args.anon
function_instrument = args.full or args.functions
inner_instrument = args.full or args.inner
call_instrument = args.full or args.calls
pointer_call_instrument = args.full or args.pointer_calls
exclude = args.exclude or []

# do the instrumentation
instrumenter = Instrumenter(database, store_dir, case_instrument=case_instrument,
                            boolop_instrument=boolop_instrument, boolop_full_instrument=boolop_full_instrument,
                            return_instrument=return_instrument, assume_tailcall=assume_tailcall,
                            inline_instrument=inline_instrument, trivial_instrument=trivial_instrument,
                            exclude=exclude,
                            main_instrument=main_instrument, main_spelling=main_spelling, main_close=main_close,
                            anon_instrument=anon_instrument,
                            function_instrument=function_instrument, inner_instrument=inner_instrument,
                            call_instrument=call_instrument, pointer_call_instrument=pointer_call_instrument)
instrumenter.parse(args.filename)
instrumenter.annotate_all(args.filename, args.output)
database.close_connection()
