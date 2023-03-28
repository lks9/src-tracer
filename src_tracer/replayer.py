import logging
import re

import angr

from .trace import Trace
from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)

class Replayer(ExplorationTechnique):

    def __init__(self, trace: Trace, functions=None, assert_points: [(int, str)]=None):
        super().__init__()
        self.iterator = trace.__iter__()
        self.assert_points = assert_points

        try:
            self.choice = next(self.iterator)
        except StopIteration:
            self.choice = None
        self.trace_ind = 0
        self.functions = functions

    def setup(self, simgr):
        self.if_addr = self._addr("_retrace_if")
        self.else_addr = self._addr("_retrace_else")
        self.wrote_int_addr = self._addr("_retrace_wrote_int")
        self.int_addr = self._addr("_retrace_int")
        # calculate mapped_base to add to addr
        mapped_base = simgr.one_active.project.loader.main_object.mapped_base
        self.assertion_addr = []
        if self.assert_points is None:
            return
        for assert_point in self.assert_points:
            addr, assertion = assert_point
            self.assertion_addr.append(addr + mapped_base)


    def _addr(self, sym_name):
        try:
            return self.project.loader.main_object.get_symbol(sym_name).rebased_addr
        except AttributeError:
            return None

    def _next_choice(self):
        if self.choice is None:
            return
        try:
            self.choice = next(self.iterator)
        except StopIteration:
            self.choice = None

    def step(self, simgr, stash='active', **kwargs):
        read_trace = True
        elem, bs = self.choice
        if elem == 'T':
            find = [self.if_addr]
            avoid = [self.else_addr, self.wrote_int_addr]
        elif elem == 'N':
            find = [self.else_addr]
            avoid = [self.if_addr, self.wrote_int_addr]
        elif self.functions and 'F' in elem:
            if bs == b'':
                # There is no func with num 0, that simply marks the end of the trace
                return simgr
            func_num = int.from_bytes(bs, "little")
            func_name = self.functions["hex_list"][func_num]["name"]
            if func_name == "main":
                func_name = "main_original"
            find = [self._addr(func_name)]
            avoid = [self.else_addr, self.if_addr, self.wrote_int_addr]
        elif elem == 'D':
            find = [self.wrote_int_addr]
            avoid = [self.else_addr, self.if_addr]
        else:
            raise ValueError(f'Trace contains unsupported element "{elem}"')

        # step to make sure the current state is not in one of the avoid state
        if self.trace_ind != 0:
            simgr.step()

        # add all the assertion point
        find.extend(self.assertion_addr)
        simgr.explore(find=find, avoid=avoid, avoid_priority=True)

        if len(simgr.found) != 1:
            l.error("Found %i canditates in simgr %s", len(simgr.found), simgr)

        if len(simgr.found) == 1 and simgr.found[0].addr in self.assertion_addr:
            # TODO: add assertion here
            # ....

            # remove the assertion addr from list
            self.assertion_addr.remove(simgr.found[0].addr)

            # set to not read the next trace element
            read_trace = False


        if read_trace and elem == 'D':
            # add the constrain for the int
            trace_int = int.from_bytes(bs, "little")
            state = simgr.found[0]
            mem_int = state.mem[self.int_addr].int.resolved
            state.solver.add(trace_int == mem_int)

        # avoid all states not in found
        simgr.drop()

        self.trace_ind = 1

        if not read_trace:
            l.debug("insert assertion in %s", simgr.found[0].__str__())
        elif bs == b'':
            l.debug("trace with %s, arrive at %s", elem, simgr.found[0].__str__())
        else:
            l.debug("trace with %s, arrive at %s", elem + str(int.from_bytes(bs, "little")), simgr.found[0].__str__())

        simgr.move(from_stash='found', to_stash='active')

        if read_trace:
            self._next_choice()

        return simgr

    def complete(self, simgr):
        return (self.choice is None) or (self.choice == ('F', b''))
