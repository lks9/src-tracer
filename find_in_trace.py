#!/usr/bin/env python3

import sys
import os
import sqlite3
import re
import monkeyhex
import concurrent.futures
import mmap

from src_tracer.trace import Trace
from src_tracer.util import Util


if len(sys.argv) >= 3:
    func_name = sys.argv[1]
    trace_file = sys.argv[2]
    database_path = os.path.dirname(trace_file)
else:
    exec_name = os.path.basename(sys.argv[0])
    usage = f"Usage: {exec_name} <func_name> <trace_file> [<trace_file> ...]"
    raise Exception(usage)

# create connection to database
database = os.path.join(database_path, 'cflow_functions.db')
if not os.path.exists(database):
    error = f"Database {database} does not exist"
    raise Exception(error)
connection = sqlite3.connect(database)

trace = Trace.from_file(trace_file)

cursor = connection.cursor()
func_nums = Util.get_numbers(cursor, func_name)
cursor.close()
connection.close()

# construct a regular expression to find the trace element
low = 0b00001000
hi  = 0b01111111
low_bytes = low.to_bytes(length=1, byteorder="little")
high_bytes = hi.to_bytes(length=1, byteorder="little")
exp = b"[" + low_bytes + b"-" + high_bytes + b"]("
exp_text = b"F("
for num in func_nums:
    num_bytes = num.to_bytes(length=(num.bit_length() + 7) // 8, byteorder="little")
    exp += num_bytes + b"|"
    exp_text += bytes(hex(num)[2:], "utf8") + b"|"
exp_text = exp_text[:-1] + b")" + b"[^0-9a-f]"
exp = exp[:-1] + b")"
pat_text = re.compile(exp_text)
pat = re.compile(exp)

def search_file(filename):
    size = os.stat(filename).st_size
    with open(filename, 'rb') as f:
        trace = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ)

    if filename[-4:] == '.txt':
        for x in pat_text.finditer(trace):
            print(f"{filename} --seek {x.start()}")
            # TODO find the closing 'R' in the trace to output --count
    else:
        for x in pat.finditer(trace):
            print(f"{filename} --seek {x.start()}")
    trace.close()

filenames = sys.argv[2:]
with concurrent.futures.ProcessPoolExecutor() as pool:
    pool.map(search_file, filenames)
