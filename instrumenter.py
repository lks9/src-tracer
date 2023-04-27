#!/usr/bin/env python3

import os
import sys
import json
import sqlite3

from src_tracer.instrumenter import Instrumenter

filename = sys.argv[1]
database_path = sys.argv[2]

# load function from database
try:
    path = os.path.join(database_path, 'cflow_function.db')
    connection = sqlite3.connect(os.path.join(database_path, 'cflow_functions.db'))
except sqlite3.OperationalError:
    sys.exit("the given path is not correct, make sure the dir exists beforehand")
cursor = connection.cursor()

instrumenter = Instrumenter(cursor)
instrumenter.parse(filename)
annotated = instrumenter.annotate_all(filename)
if annotated:
    connection.commit()
cursor.close()
connection.close()
