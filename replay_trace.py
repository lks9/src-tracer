#!/usr/bin/env python3

import sys
import logging

import claripy
import angr

from print_trace import trace_to_string

def addr(p, sym_name):
    try:
        return p.loader.main_object.get_symbol(sym_name).rebased_addr
    except:
        return None

def make_globals_symbolic(p, state):
    for obj in p.loader.all_elf_objects:
        for section in obj.sections:
            if section.name == ".data":
                data_bvs = claripy.BVS(".data", 8*(section.max_addr - section.min_addr))
                state.memory.store(section.min_addr, data_bvs)
            elif section.name == ".bss":
                bss_bvs = claripy.BVS(".bss", 8*(section.max_addr - section.min_addr))
                state.memory.store(section.min_addr, bss_bvs)
    writing_addr = addr(p, "_cflow_writing")
    if writing_addr:
        state.mem[writing_addr].int = 1

def start_state(p, func_name: str):
    addr = p.loader.main_object.get_symbol(func_name).rebased_addr
    state = p.factory.blank_state(addr=addr)
    make_globals_symbolic(p, state)
    # optimize a bit
    state.options["COPY_STATES"] = False
    return state


if __name__ == "__main__":
    # better hex printing
    try:
        import monkeyhex
    except ModuleNotFoundError:
        pass

    # silence some loggers for angr's sub-classes:
    logging.getLogger("cle.loader").setLevel(logging.CRITICAL)
    logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.CRITICAL)
    logging.getLogger("angr.engines.successors").setLevel(logging.CRITICAL)

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

    trace_str = trace_to_string(trace_file)

    try:
        import json
        with open("cflow_functions.json") as f:
            functions = json.load(f)
    except FileNotFoundError:
        functions = None
    p = angr.Project(binary_name)
    # start_state, simulation manager
    simgr = p.factory.simulation_manager(start_state(p, func_name), auto_drop=("avoid",))
    # create a replayer
    replayer = angr.exploration_techniques.replayer.Replayer(trace_str, functions)
    simgr.use_technique(replayer)
    simgr.run()
    state = simgr.active[0]
