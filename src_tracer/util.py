#!/usr/bin/env python3

import claripy

class Util:

    @staticmethod
    def addr(p, sym_name):
        try:
            return p.loader.main_object.get_symbol(sym_name).rebased_addr
        except:
            return None

    @staticmethod
    def make_globals_symbolic(p, state):
        for obj in p.loader.all_elf_objects:
            for section in obj.sections:
                if section.name == ".data":
                    data_bvs = claripy.BVS(".data", 8*(section.max_addr - section.min_addr))
                    state.memory.store(section.min_addr, data_bvs)
                elif section.name == ".bss":
                    bss_bvs = claripy.BVS(".bss", 8*(section.max_addr - section.min_addr))
                    state.memory.store(section.min_addr, bss_bvs)
        writing_addr = Util.addr(p, "_cflow_writing")
        if writing_addr:
            state.mem[writing_addr].int = 1

    @staticmethod
    def start_state(p, func_name: str):
        addr = p.loader.main_object.get_symbol(func_name).rebased_addr
        state = p.factory.blank_state(addr=addr)
        Util.make_globals_symbolic(p, state)
        # optimize a bit
        state.options["COPY_STATES"] = False
        return state

