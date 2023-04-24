#!/usr/bin/env python3

import sys
import json
import sqlite3

from src_tracer.instrumenter import Instrumenter

filename = sys.argv[1]

# load function from database
connection = sqlite3.connect('cflow_functions.db')
cursor = connection.cursor()

instrumenter = Instrumenter(cursor)
instrumenter.parse(filename)
annotated = instrumenter.annotate_all(filename)
if annotated:
    connection.commit()
cursor.close()
connection.close()
