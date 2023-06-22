import logging

import claripy
import angr

from angr.sim_type import parse_signature, parse_type


from .trace import Trace

log = logging.getLogger(__name__)

from enum import Enum, auto


class AssertResult(Enum):
    """
    Basically the usual three valued logic VIOLATED (= False), UNSURE and PASSED (= True).
    Extra element NEVER_PASSED is neutral to all operations.
    """

    NEVER_PASSED = auto()
    PASSED = auto()
    VIOLATED = auto()
    UNSURE = auto()

    def And(a1, a2):
        """
        Logical And
        """
        if AssertResult.VIOLATED in (a1, a2):
            return AssertResult.VIOLATED
        elif AssertResult.UNSURE in (a1, a2):
            return AssertResult.UNSURE
        elif AssertResult.PASSED in (a1, a2):
            return AssertResult.PASSED
        else:
            return AssertResult.NEVER_PASSED

    def Or(a1, a2):
        """
        Logical Or
        """
        if AssertResult.PASSED in (a1, a2):
            return AssertResult.PASSED
        elif AssertResult.UNSURE in (a1, a2):
            return AssertResult.UNSURE
        elif AssertResult.VIOLATED in (a1, a2):
            return AssertResult.VIOLATED
        else:
            return AssertResult.NEVER_PASSED

    def Not(a):
        """
        Logical Not
        """
        if a == AssertResult.PASSED:
            return AssertResult.VIOLATED
        elif a == AssertResult.UNSURE:
            return AssertResult.UNSURE
        elif a == AssertResult.VIOLATED:
            return AssertResult.PASSED
        else:
            return AssertResult.NEVER_PASSED

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
        self.is_retrace_addr = self.addr("_is_retrace_mode")

        # ghost code
        self.ghost_start_addr = self.addr("_retrace_ghost_start")
        self.ghost_end_addr = self.addr("_retrace_ghost_end")
        self.in_ghost_addr = self.addr("_retrace_in_ghost")

        self.assert_names_addr = self.addr("_retrace_assert_names")
        self.asserts_addr = self.addr("_retrace_asserts")
        self.assert_idx_addr = self.addr("_retrace_assert_idx")
        self.assert_passed_addr = self.addr("_retrace_assert_passed")

        self.assume_name_addr = self.addr("_retrace_assume_name")
        self.assume_addr = self.addr("_retrace_assume")
        self.assume_passed_addr = self.addr("_retrace_assume_passed")

        self.prop_start_addr = self.addr("_retrace_prop_start")
        self.prop_is_assert_addr = self.addr("_retrace_prop_is_assert")
        self.prop_is_assume_addr = self.addr("_retrace_prop_is_assume")
        self.prop_passed_addr = self.addr("_retrace_prop_passed")

        self.asserts_addr = self.addr("_retrace_asserts")

    def addr(self, sym_name):
        try:
            return self.p.loader.main_object.get_symbol(sym_name).rebased_addr
        except AttributeError:
            return None

    def check_assertion(self, state, index):
        val = state.mem[self.asserts_addr + index].bool.resolved
        solver_res = state.solver.eval_upto(val, 2)
        if (False in solver_res) and (True in solver_res):
            return AssertResult.UNSURE
        elif False in solver_res:
            return AssertResult.VIOLATED
        elif True in solver_res:
            return AssertResult.PASSED
        else:
            # state is already UNSAT!
            raise Exception

    def assert_result(self, state, label: str):
        res = AssertResult.NEVER_PASSED
        for index, cur_label in enumerate(self.asserts_list):
            if cur_label == label:
                cur_res = self.check_assertion(state, index)
                res = AssertResult.And(res, cur_res)
        return res

    def check_all_assertions(self, state):
        res = AssertResult.NEVER_PASSED
        count = state.mem[self.assert_idx_addr].int.concrete
        for index in range(count):
            label = state.mem[self.assert_names_addr + 8*index].deref.string.concrete.decode()
            cur_res = self.check_assertion(state, index)
            res = AssertResult.And(res, cur_res)
            log.debug(f'Assertion "{label}": {cur_res.name}')
        return res

    def int_of_elem(self, elem: str):
        sub = elem[1:]
        if sub == "":
            return 0
        return int(sub)

    def make_globals_symbolic(self, state):
        for obj in self.p.loader.all_elf_objects:
            for section in obj.sections:
                if section.name == ".data" or section.name == ".bss":
                    for i in range(section.max_addr- section.min_addr):
                        data = state.solver.BVS("data" + str(i) + section.name, 8)
                        state.memory.store(section.min_addr + i, data)
        if self.is_retrace_addr:
            state.mem[self.is_retrace_addr].bool = True
        if self.assert_idx_addr:
            state.mem[self.assert_idx_addr].int = 0
        if self.in_ghost_addr:
            state.mem[self.in_ghost_addr].bool = False

    def start_state(self, func_name: str, **kwargs):
        addr = self.p.loader.main_object.get_symbol(func_name).rebased_addr
        # prototype is just a placeholder to silence a warning in angr
        prototype = parse_signature("void *f()")
        state = self.p.factory.call_state(addr=addr, prototype=prototype, **kwargs)
        self.make_globals_symbolic(state)
        return state

    def find_letter(self, letter):
        if letter == 'T':
            return self.if_addr
        elif letter == 'N':
            return self.else_addr
        elif letter == 'R':
            return self.return_addr
        elif letter == 'F' or letter == 'A':
            return self.fun_call_addr
        elif letter == 'D':
            return self.wrote_int_addr
        else:
            raise ValueError(f'Trace contains unsupported element "{letter}"')

    def find(self, elem):
        return {self.find_letter(elem.letter)}

    @property
    def reals(self):
        return {self.if_addr, self.else_addr, self.wrote_int_addr, self.return_addr, self.fun_call_addr}

    @property
    def ghosts(self):
        return {self.ghost_start_addr, self.ghost_end_addr,
                self.assert_passed_addr, self.assume_passed_addr, self.prop_start_addr, self.prop_passed_addr}

    def handle_ghost(self, simgr, debug, merging=False, assumptions=[], assertions=[]):

        self.merge(simgr, 'ghost', merging)
        # step once so we don't run into ghost start addr again
        simgr.step('ghost')

        while simgr.ghost != []:
            while simgr.ghost != []:
                simgr.explore(stash='ghost', find=self.ghosts, find_stash='ghost_handle')

            simgr.move(from_stash='ghost_handle', to_stash='assertions',
                       filter_func=lambda s: s.solver.eval(s.ip) == self.assert_passed_addr)
            simgr.move(from_stash='ghost_handle', to_stash='assume',
                       filter_func=lambda s: s.solver.eval(s.ip) == self.assume_passed_addr)
            simgr.move(from_stash='ghost_handle', to_stash='propose',
                       filter_func=lambda s: s.solver.eval(s.ip) == self.prop_start_addr)
            simgr.move(from_stash='ghost_handle', to_stash='propose_end',
                       filter_func=lambda s: s.solver.eval(s.ip) == self.prop_passed_addr)
            simgr.move(from_stash='ghost_handle', to_stash='ghost_end',
                       filter_func=lambda s: s.solver.eval(s.ip) == self.ghost_end_addr)

            # handle propositions
            for state in simgr.propose:
                index = state.mem[self.assert_idx_addr].int.concrete
                label = state.mem[self.assert_names_addr + 8*index].deref.string.concrete.decode()
                log.debug(f'Proposition "{label}" with index {index}')
                if label in assertions:
                    state.mem[self.prop_is_assert_addr].bool = True
                else:
                    state.mem[self.prop_is_assert_addr].bool = False
                if label in assumptions:
                    state.mem[self.prop_is_assume_addr].bool = True
                else:
                    state.mem[self.prop_is_assume_addr].bool = False

            # handle prospose end
            for state in simgr.propose_end:
                if state.mem[self.prop_is_assume_addr].bool.concrete:
                    mem_assume = state.mem[self.assume_addr].bool.resolved
                    state.solver.add(mem_assume)

            # handle assumptions
            for state in simgr.assume:
                mem_assume = state.mem[self.assume_addr].bool.resolved
                state.solver.add(mem_assume)

            if debug:
                for state in simgr.assertions:
                    index = state.mem[self.assert_idx_addr].int.concrete
                    label = state.mem[self.assert_names_addr + 8*index].deref.string.concrete.decode()
                    log.debug(f'Assertion "{label}" with index {index}')
                for state in simgr.assume:
                    if state.satisfiable():
                        label = state.mem[self.assume_name_addr].deref.string.concrete.decode()
                        log.debug(f'Assumption "{label}"')

            simgr.step(stash='assertions')
            simgr.move(from_stash='assertions', to_stash='ghost')
            simgr.step(stash='assume')
            simgr.move(from_stash='assume', to_stash='ghost')
            simgr.step(stash='propose')
            simgr.move(from_stash='propose', to_stash='ghost')
            simgr.step(stash='propose_end')
            simgr.move(from_stash='propose_end', to_stash='ghost')

            for state in simgr.ghost_handle:
                raise ValueError("Nested ghosts are currently not supported")

        self.merge(simgr, 'ghost_end', merging)
        simgr.move(from_stash='ghost_end', to_stash='active')

    def merge(self, simgr, stash, merging=True):
        if not merging:
            return
        count = len(simgr.stashes[stash])
        if count > 1:
            log.debug(f"Merging {count} states in '{stash}'")
            simgr.merge(stash=stash)

    def try_solve_unconstrained(self, elem, simgr, database, to_stash='active'):
        if elem.letter == 'F' and database:
            fun_num = int.from_bytes(elem.bs, "little")
            try:
                fun_name = database.get_name(fun_num)
                fun_addr = self.addr(fun_name)
                for ustate in simgr.unconstrained:
                    ustate.solver.add(ustate.ip == fun_addr)
                log.debug("Solved! Unconstrained state(s) constrained to the next function's address.")
                simgr.move(from_stash='unconstrained', to_stash=to_stash)
                return True
            except Exception:
                pass
        log.warning("Unconstrained state(s) and constraining not possible.")
        return False

    def follow_trace(self, trace: Trace, func_name: str, database=None, merging=False, assumptions=[],
                     assertions=[], finish_dead=True, **kwargs):
        # function name not given?
        if not func_name:
            elem = next(iter(trace))
            if elem.letter != 'F':
                raise ValueError(f'Trace contains first element "{elem.letter}"')
            func_num = int.from_bytes(elem.bs, "little")
            func_name = database.get_name(func_num)
            log.debug('Starting with function "%s"', func_name)

        # start_state, simulation manager
        simgr = self.p.factory.simulation_manager(self.start_state(func_name, **kwargs))

        debug = log.isEnabledFor(logging.DEBUG)

        # create all stashes we will use to avoid any AttributeError
        simgr.populate('active', [])
        simgr.populate('traced', [])
        simgr.populate('ghost', [])
        simgr.populate('ghost_handle', [])
        simgr.populate('ghost_end', [])
        simgr.populate('reals', [])
        simgr.populate('avoid', [])
        simgr.populate('unsat', [])
        simgr.populate('unconstrained', [])
        simgr.populate('deadended', [])

        # do the actual tracing
        for elem in trace:

            # PART 0: clean up from previous iteration
            # step once to be sure that we don't stay in the current state
            # (for correct treatment of "T" or "N" elements, "TT" should match if_addr in two different states)
            simgr.step('traced')
            # start over with active
            simgr.move(from_stash='traced', to_stash='active')

            if simgr.active:
                state = simgr.active[0]

            # PART 1: find ghost code
            while simgr.active != []:
                while simgr.active != []:
                    simgr.explore(find=self.ghost_start_addr, avoid=self.reals,
                                  find_stash='ghost', avoid_stash='reals')
                if simgr.ghost != []:
                    self.handle_ghost(simgr, debug, merging, assumptions, assertions)
            simgr.move(from_stash='reals', to_stash='active')

            # PART 2: find next element
            find = self.find(elem)
            avoid = self.reals.difference(find)
            while simgr.active != [] or simgr.unconstrained != []:
                while simgr.active != []:
                    simgr.explore(find=find, avoid=avoid, find_stash='traced')

                # PART 2.5: handle unconstrained
                if simgr.unconstrained != []:
                    self.try_solve_unconstrained(elem, simgr, database)
                    # to break out of PART 2 loop if try_solve failed
                    simgr.move(from_stash='unconstrained', to_stash='deadended')
                    # final check is in PART 3

            # PART 3: nothing found?
            if simgr.traced == []:
                log.warning("Could not find %s at all in simgr %s", elem.letter, simgr)
                return (simgr, state)

            # PART 4: merge states
            self.merge(simgr, 'traced', merging)

            # PART 5: add constraints for functions and data
            if elem.letter == 'D':
                # add the constrain for the int
                trace_int = int.from_bytes(elem.bs, "little")
                for state in simgr.traced:
                    mem_int = state.mem[self.int_addr].with_type(parse_type("long long int")).resolved
                    state.solver.add(mem_int == trace_int)
            elif elem.letter == 'F':
                fun_num = int.from_bytes(elem.bs, "little")
                for state in simgr.traced:
                    mem_num = state.mem[self.fun_num_addr].int.resolved
                    state.solver.add(mem_num == fun_num)

            # PART 6: debugging
            if debug:
                name = None
                if not elem.bs == b'':
                    num = int.from_bytes(elem.bs, "little")
                    if elem.letter == 'F' and database:
                        name = database.get_name(num)
                if len(simgr.traced) > 1:
                    log.debug(elem.pretty(name=name) + f" (found {len(simgr.traced)})")
                else:
                    log.debug(elem.pretty(name=name))

            # PART 7: drop all states not in traced
            simgr.drop(stash="avoid")
            simgr.drop(stash="unsat")

        if finish_dead:
            simgr.step('traced')
            # the same as PART 1: find ghost code
            simgr.move(from_stash='traced', to_stash='active')
            while simgr.active != []:
                while simgr.active != []:
                    simgr.explore(find=self.ghost_start_addr, avoid=self.reals,
                                  find_stash='ghost', avoid_stash='reals')
                if simgr.ghost != []:
                    self.handle_ghost(simgr, debug, merging, assumptions, assertions)
            simgr.move(from_stash='reals', to_stash='active')

            # we could get unconstrained instead of deadended
            simgr.move(from_stash='unconstrained', to_stash='deadended')

            return (simgr, simgr.deadended[0])

        return (simgr, simgr.traced[0])
