#include "cflow_inst.h"

void _retrace_if(void) {}

void _retrace_else(void) {}

unsigned int _retrace_int;

void _retrace_wrote_int(void) {}

unsigned int _retrace_num(unsigned int num) {
    _retrace_int = num;
    _retrace_wrote_int();
    return num;
}
