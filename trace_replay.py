#!/usr/bin/env python3

import logging
import sys

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
    func_name = "main"
    trace_file = sys.argv[2]
elif len(sys.argv) == 4:
    binary_name = sys.argv[1]
    func_name = sys.argv[2]
    trace_file = sys.argv[3]
else:
    usage = f"Usage: python3 -i {sys.argv[0]} <binary_name> <func_name> <trace_file>"
    raise Exception(usage)

trace = Trace.from_file(trace_file)

try:
    import json
    with open("cflow_functions.json") as f:
        functions = json.load(f)
except FileNotFoundError:
    functions = None

source_tracer = SourceTraceReplayer(binary_name)
simgr = source_tracer.follow_trace(trace, func_name, functions)
state = simgr.found[0]
