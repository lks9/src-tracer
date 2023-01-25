#!/usr/bin/env python3

import sys
import logging
import re

import claripy
import angr

l = logging.getLogger(__name__)

class SourceTraceReplayer:

    def __init__(self, binary_name, fd=0, **kwargs):
        self.p = angr.Project(binary_name, **kwargs)

        self.fd = fd
        self.fd_addr = self.addr("_cflow_fd")

    def addr(self, sym_name):
        return self.p.loader.main_object.get_symbol(sym_name).rebased_addr

    def int_of_elem(self, elem: str):
        sub = elem[1:]
        if sub == "":
            return 0
        return int(sub)

    # dump the file given for a state s
    def dump(self, state):
        if self.fd == 0:
            # maybe correct fd in memory (results 0 otherwise if still symbolic)
            self.fd = state.mem[self.fd_addr].int.concrete
            if self.fd == 0:
                return b''
        try:
            return state.posix.dumps(self.fd)
        except:
            return b''

    def make_globals_symbolic(self, state):
        for obj in self.p.loader.all_elf_objects:
            for section in obj.sections:
                if section.name == ".data":
                    data_bvs = claripy.BVS(".data", 8*(section.max_addr - section.min_addr))
                    state.memory.store(section.min_addr, data_bvs)
                elif section.name == ".bss":
                    bss_bvs = claripy.BVS(".bss", 8*(section.max_addr - section.min_addr))
                    state.memory.store(section.min_addr, bss_bvs)
        state.mem[self.addr("_cflow_writing")].int = 1

    def start_state(self, func_name: str):
        if func_name == "main":
            # instrumentation renamed "main" to "main_original"
            func_name = "main_original"
        addr = self.p.loader.main_object.get_symbol(func_name).rebased_addr
        state = self.p.factory.blank_state(addr=addr)
        self.make_globals_symbolic(state)
        # optimize a bit
        state.options["COPY_STATES"] = False
        return state

    def follow_trace(self, trace_str: str, func_name: str):
        # start_state, simulation manager
        simgr = self.p.factory.simulation_manager(self.start_state(func_name), auto_drop=("avoid",))

        # Split trace_str into elements
        trace_str = trace_str.encode()
        elems = re.findall(br"[A-Z][0-9a-z]*", trace_str)

        # do the actual tracing
        trace_pos = 0
        for elem in elems:
            find = lambda s: self.dump(s)[trace_pos:] == elem
            avoid = lambda s: self.dump(s)[trace_pos:] not in (b'', elem)
            simgr.explore(find=find, avoid=avoid, avoid_priority=True)

            if len(simgr.found) != 1:
                l.error("Found %i canditates in simgr %s", len(simgr.found), simgr)

            # avoid all states not in found
            simgr.drop()
            # start over with active
            simgr.move(from_stash='found', to_stash='active')

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
        usage = "Usage: python3 -i {} <binary_name> <func_name> <trace_file>".format(sys.argv[0])
        raise Exception(usage)

    with open(trace_file) as f:
        trace_str = f.read()

    source_tracer = SourceTraceReplayer(binary_name)
    simgr = source_tracer.follow_trace(trace_str, func_name)
    state = simgr.active[0]
