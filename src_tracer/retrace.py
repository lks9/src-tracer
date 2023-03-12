import logging

import claripy
import angr

from .trace import Trace

log = logging.getLogger(__name__)


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

    def follow_trace(self, trace: Trace, func_name: str, functions=None):
        # start_state, simulation manager
        simgr = self.p.factory.simulation_manager(self.start_state(func_name), auto_drop=("avoid",))

        debug = log.isEnabledFor(logging.DEBUG)

        # do the actual tracing
        for (elem, bs) in trace:
            if elem == 'T':
                find = self.if_addr
                avoid = [self.else_addr, self.wrote_int_addr]
            elif elem == 'N':
                find = self.else_addr
                avoid = [self.if_addr, self.wrote_int_addr]
            elif functions and elem == 'F':
                if bs == b'':
                    # There is no func with num 0, that simply marks the end of the trace
                    return simgr
                func_num = int.from_bytes(bs, "little")
                func_name = functions["hex_list"][func_num]["name"]
                find = self.addr(func_name)
                avoid = [self.else_addr, self.if_addr, self.wrote_int_addr]
            elif elem == 'D':
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
                log.error("Found %i canditates in simgr %s", len(simgr.found), simgr)

            if elem == 'D':
                # add the constrain for the int
                trace_int = int.from_bytes(bs, "little")
                state = simgr.found[0]
                mem_int = state.mem[self.int_addr].int.resolved
                state.solver.add(mem_int == trace_int)

            if debug:
                num = int.from_bytes(bs, "little")
                log.debug(f"{elem}{num:x}")

            # avoid all states not in found
            simgr.drop()

        return simgr
