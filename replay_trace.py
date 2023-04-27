#!/usr/bin/env python3

import logging
import sys
import sqlite3
import os

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

if len(sys.argv) == 3:
    binary_name = sys.argv[1]
    func_name = None
    trace_file = sys.argv[2]
    database_path = ""
elif len(sys.argv) == 4:
    binary_name = sys.argv[1]
    func_name = None
    trace_file = sys.argv[2]
    database_path = sys.argv[3]
elif len(sys.argv) == 5:
    binary_name = sys.argv[1]
    func_name = sys.argv[2]
    trace_file = sys.argv[3]
    database_path = sys.argv[4]
else:
    usage = f"Usage: python3 -i {sys.argv[0]} <binary_name> <func_name> <trace_file> <func_database_dir_path>"
    raise Exception(usage)

trace = Trace.from_file(trace_file)

# create connection to database
try:
    connection = sqlite3.connect(os.path.join(database_path, 'cflow_functions.db'))
except sqlite3.OperationalError:
    error = "the given path is not correct, make sure the dir exists beforehand"
    raise Exception(error)
cursor = connection.cursor()

source_tracer = SourceTraceReplayer(binary_name, auto_load_libs=False, use_sim_procedures=False)
(simgr, state) = source_tracer.follow_trace(trace, func_name, cursor)

res = source_tracer.check_all_assertions(state)

print()
print(f"Final assertion check result: {res.name}")
print()
cursor.close()
connection.close()
