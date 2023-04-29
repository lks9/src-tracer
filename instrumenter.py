#!/usr/bin/env python3

import sys
import os
import json
import sqlite3

from src_tracer.instrumenter import Instrumenter

if len(sys.argv) == 2:
    filename = sys.argv[1]
    trace_store_dir = os.path.dirname(filename)
elif len(sys.argv) == 3:
    filename = sys.argv[1]
    trace_store_dir = sys.argv[2]
else:
    usage = f"Usage: python3 {sys.argv[0]} <filename> [<trace_store_dir>]"
    raise Exception(usage)

# create connection to database
try:
    connection = sqlite3.connect(os.path.join(trace_store_dir, 'cflow_functions.db'))
except sqlite3.OperationalError:
    error = "the given path is not correct, make sure the dir exists beforehand"
    raise Exception(error)

cursor = connection.cursor()

instrumenter = Instrumenter(cursor, trace_store_dir)
instrumenter.parse(filename)
annotated = instrumenter.annotate_all(filename)
if annotated:
    connection.commit()
cursor.close()
connection.close()
