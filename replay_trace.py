#!/usr/bin/env python3

import sys
import logging
import re

import claripy
import angr

from print_trace import trace_to_string

l = logging.getLogger(__name__)

class SourceTraceReplayer:

    def __init__(self, binary_name, **kwargs):
        self.p = angr.Project(binary_name, **kwargs)

        self.if_addr = self.addr("_cflow_if")
        self.else_addr = self.addr("_cflow_else")
        self.writing_addr = self.addr("_cflow_writing")
        self.wrote_int_addr = self.addr("_cflow_wrote_int")
        self.int_addr = self.addr("_cflow_int")

    def addr(self, sym_name):
        try:
            return self.p.loader.main_object.get_symbol(sym_name).rebased_addr
        except AttributeError:
            return None

    def int_of_elem(self, elem: str):
        sub = elem[1:]
        if sub == "":
            return 0
        return int(sub)

    def make_globals_symbolic(self, state):
        for obj in self.p.loader.all_elf_objects:
            for section in obj.sections:
                if section.name == ".data":
                    data_bvs = claripy.BVS(".data", 8*(section.max_addr - section.min_addr))
                    state.memory.store(section.min_addr, data_bvs)
                elif section.name == ".bss":
                    bss_bvs = claripy.BVS(".bss", 8*(section.max_addr - section.min_addr))
                    state.memory.store(section.min_addr, bss_bvs)
        if self.writing_addr:
            state.mem[self.writing_addr].int = 1

    def start_state(self, func_name: str):
        addr = self.p.loader.main_object.get_symbol(func_name).rebased_addr
        state = self.p.factory.blank_state(addr=addr)
        self.make_globals_symbolic(state)
        # optimize a bit
        state.options["COPY_STATES"] = False
        return state

    def follow_trace(self, trace_str: str, func_name: str, functions=None):
        # start_state, simulation manager
        simgr = self.p.factory.simulation_manager(self.start_state(func_name), auto_drop=("avoid",))

        # Split trace_str into elements
        trace_str = trace_str.encode()
        elems = re.findall(br"[A-Z][0-9a-z]*", trace_str)

        # do the actual tracing
        trace_pos = 0
        for elem in elems:
            if elem == b"T":
                find = self.if_addr
                avoid = [self.else_addr, self.wrote_int_addr]
            elif elem == b"N":
                find = self.else_addr
                avoid = [self.if_addr, self.wrote_int_addr]
            elif functions and b"F" in elem:
                func_num = int(elem[1:], 16)
                if func_num == 0:
                    # There is no func with num 0, that simply marks the end of the trace
                    return simgr
                func_name = functions["hex_list"][func_num]["name"]
                find = self.addr(func_name)
                avoid = [self.else_addr, self.if_addr, self.wrote_int_addr]
            elif b"D" in elem:
                find = self.wrote_int_addr
                avoid = [self.else_addr, self.if_addr]
            else:
                raise ValueError(f'Trace contains unsupported element "{elem}"')

            try:
                # step once to be sure that we don't stay in the current state
                # (for correct treatment of "T" or "N" elements, "TT" should match if_addr in two different states)
                simgr.step('found')
                # start over with active
                simgr.move(from_stash='found', to_stash='active')
            except AttributeError:
                # no stash 'found'...
                pass

            simgr.explore(find=find, avoid=avoid, avoid_priority=True)

            if len(simgr.found) != 1:
                l.error("Found %i canditates in simgr %s", len(simgr.found), simgr)

            if b"D" in elem:
                # add the constrain for the int
                trace_int = int(elem[1:], 16)
                state = simgr.found[0]
                mem_int = state.mem[self.int_addr].int.resolved
                state.solver.add(trace_int == mem_int)

            # avoid all states not in found
            simgr.drop()

            trace_pos += len(elem)
            l.debug("%s", elem.decode())


        return simgr


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

    # make the current logger debug
    l.setLevel(logging.DEBUG)

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

    source_tracer = SourceTraceReplayer(binary_name)
    simgr = source_tracer.follow_trace(trace_str, func_name, functions)
    state = simgr.found[0]
