#!/usr/bin/env python3

import sys

from src_tracer.trace import Trace

filename = sys.argv[1]

trace = Trace.from_file(filename)

print(trace)
