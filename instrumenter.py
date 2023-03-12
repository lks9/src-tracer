#!/usr/bin/env python3

import sys
import json

from src_tracer.instrumenter import Instrumenter

filename = sys.argv[1]

try:
    # We don't want to overwrite existing func_nums...
    with open("cflow_functions.json") as f:
        # print("Reading cflow_functions.json")
        functions = json.load(f)
except FileNotFoundError:
    # print("Creating cflow_functions.json")
    functions = None

instrumenter = Instrumenter(functions)
instrumenter.parse(filename)
annotated = instrumenter.annotate_all(filename)
if (annotated):
    with open("cflow_functions.json", "w") as f:
        # print("Writing cflow_functions.json")
        json.dump(instrumenter.functions, f, indent=2)
