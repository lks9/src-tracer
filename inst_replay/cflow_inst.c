#include "cflow_inst.h"

void _cflow_if(void) {}

void _cflow_else(void) {}

unsigned int _cflow_int;

void _cflow_wrote_int(void) {}

unsigned int _cflow_put_num(unsigned int num) {
    _cflow_int = num;
    _cflow_wrote_int();
    return num;
}
