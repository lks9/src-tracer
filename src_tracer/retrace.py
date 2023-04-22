import logging

import claripy
import angr

from .trace import Trace

log = logging.getLogger(__name__)

from enum import Enum, auto


class AssertResult(Enum):
    NEVER_PASSED = auto()
    PASSED = auto()
    VIOLATED = auto()
    UNSURE = auto()
    UNSAT = auto()


class SourceTraceReplayer:

    def __init__(self, binary_name, **kwargs):
        self.p = angr.Project(binary_name, **kwargs)

        self.if_addr = self.addr("_retrace_if")
        self.else_addr = self.addr("_retrace_else")
        self.return_addr = self.addr("_retrace_return")
        self.fun_call_addr = self.addr("_retrace_fun_call")
        self.fun_num_addr = self.addr("_retrace_fun_num")
        self.wrote_int_addr = self.addr("_retrace_wrote_int")
        self.int_addr = self.addr("_retrace_int")
        self.assert_passed_addr = self.addr("_retrace_assert_passed")
        self.assert_values_addr = self.addr("_retrace_assert_values")
        self.assert_index_addr = self.addr("_retrace_assert_index")
        self.assert_label_addr = self.addr("_retrace_assert_label")
        self.asserts_list = []
        self.is_retrace_addr = self.addr("_is_retrace_mode")

    def addr(self, sym_name):
        try:
            return self.p.loader.main_object.get_symbol(sym_name).rebased_addr
        except AttributeError:
            return None

    def assert_result(self, state, label: str):
        if label in self.asserts_list:
            index = self.asserts_list.index(label)
            val = state.mem[self.assert_values_addr + index].bool.resolved
            solver_res = state.solver.eval_upto(val, 2)
            if (False in solver_res) and (True in solver_res):
                return AssertResult.UNSURE
            elif False in solver_res:
                return AssertResult.PASSED
            elif True in solver_res:
                return AssertResult.VIOLATED
            else:
                return AssertResult.UNSAT
        return AssertResult.NEVER_PASSED

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
        if self.is_retrace_addr:
            state.mem[self.is_retrace_addr].bool = True

    def start_state(self, func_name: str):
        addr = self.p.loader.main_object.get_symbol(func_name).rebased_addr
        state = self.p.factory.blank_state(addr=addr)
        self.make_globals_symbolic(state)
        # optimize a bit
        state.options["COPY_STATES"] = False
        state.options["ALL_FILES_EXIST"] = False
        state.options["ANY_FILE_MIGHT_EXIST"] = True
        #state.options["LAZY_SOLVES"] = True
        #state.options["CONSERVATIVE_READ_STRATEGY"] = True
        return state

    def follow_trace(self, trace: Trace, func_name: str, functions=None):
        # start_state, simulation manager
        if not func_name:
            (elem, bs) = next(iter(trace))
            if elem != 'F':
                raise ValueError(f'Trace contains first element "{elem}"')
            func_num = int.from_bytes(bs, "little")
            func_name = functions["hex_list"][func_num]["name"]
            log.debug('Starting with function "%s"', func_name)

        simgr = self.p.factory.simulation_manager(self.start_state(func_name))

        debug = log.isEnabledFor(logging.DEBUG)

        # do the actual tracing
        for (elem, bs) in trace:
            if elem == 'T':
                find = [self.if_addr]
                avoid = [self.else_addr, self.wrote_int_addr, self.return_addr, self.fun_call_addr]
            elif elem == 'N':
                find = [self.else_addr]
                avoid = [self.if_addr, self.wrote_int_addr, self.return_addr, self.fun_call_addr]
            elif elem == 'R':
                find = [self.return_addr]
                avoid = [self.if_addr, self.else_addr, self.wrote_int_addr, self.fun_call_addr]
            elif elem == 'F':
                if bs == b'':
                    # There is no func with num 0, that simply marks the end of the trace
                    return (simgr, simgr.found[0])
                find = [self.fun_call_addr]
                avoid = [self.if_addr, self.else_addr, self.wrote_int_addr, self.return_addr]
            elif elem == 'D':
                find = [self.wrote_int_addr]
                avoid = [self.else_addr, self.if_addr, self.return_addr, self.fun_call_addr]
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

            if simgr.active:
                state = simgr.active[0]

            # find also asserts
            find += [self.assert_passed_addr]

            while len(simgr.active) != 0:
                simgr.explore(find=find, avoid=avoid, avoid_priority=True)
                if simgr.found == []:
                    if simgr.unconstrained != [] and elem == 'F' and functions:
                        fun_num = int.from_bytes(bs, "little")
                        fun_name = functions["hex_list"][fun_num]["name"]
                        fun_addr = self.addr(fun_name)
                        for ustate in simgr.unconstrained:
                            ustate.solver.add(ustate.ip == fun_addr)
                        log.debug("State was unconstrained, so constrained to the address of the next function.")
                        simgr.move(from_stash='unconstrained', to_stash='active')
                    else:
                        log.error("Could not find %s at all", elem)
                        return (simgr, state)

            if len(simgr.found) != 1:
                log.warning("Found %i canditates in simgr %s", len(simgr.found), simgr)

            # handle asserts
            while True:
                found_assert = False
                for state in simgr.found:
                    if state.solver.eval(state.ip) == self.assert_passed_addr:
                        found_assert = True
                        # assert_label is a string
                        assert_label = state.mem[self.assert_label_addr].string.concrete.decode()
                        # save the assertion label with index in the list
                        if assert_label not in self.asserts_list:
                            self.asserts_list.append(assert_label)
                        index = self.asserts_list.index(assert_label)
                        log.debug("Assertion '" + assert_label + "' with index " + str(index))
                        # in the next step the program uses the index to save the assertion value in the array
                        state.mem[self.assert_index_addr].int = index
                if found_assert:
                    simgr.move(from_stash='found', to_stash='active')
                    simgr.step(selector_func=lambda state: state.solver.eval(state.ip) == self.assert_passed_addr)
                    # rerun explore to find the element (after the assertion)
                    simgr.explore(find=find, avoid=avoid, avoid_priority=True)
                    continue
                else:
                    break

            if elem == 'D':
                # add the constrain for the int
                trace_int = int.from_bytes(bs, "little")
                for state in simgr.found:
                    mem_int = state.mem[self.int_addr].int.resolved
                    state.solver.add(mem_int == trace_int)
            elif elem == 'F':
                fun_num = int.from_bytes(bs, "little")
                for state in simgr.found:
                    mem_num = state.mem[self.fun_num_addr].int.resolved
                    state.solver.add(mem_num == fun_num)

            if debug:
                if bs == b'':
                    log.debug(f"{elem}")
                else:
                    num = int.from_bytes(bs, "little")
                    if elem == 'F' and functions:
                        name = functions["hex_list"][num]["name"]
                        log.debug(f"{elem}{num:x} {name}")
                    else:
                        log.debug(f"{elem}{num:x}")

            # avoid all states not in found
            simgr.drop(stash="avoid")
            simgr.drop(stash="unsat")

        return (simgr, simgr.found[0])
