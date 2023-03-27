#include "src_tracer.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int _trace_fd;
bool _trace_writing = false;

unsigned char _trace_if_byte;
int _trace_if_count;

void _trace_write(const void *buf, int count) {
    if (_trace_writing) {
        _trace_writing = false;
        if (write(_trace_fd, buf, count) == -1) {
            // some write error occured
            // do not reset _trace_writing, instead abort trace recording
            return;
        }
        _trace_writing = true;
    }
}

// same as the macro version
// but returns num
// can be used inside switch conditions
unsigned int _trace_num(char type, unsigned int num) {
    _TRACE_NUM(type, num)
    return num;
}

void _trace_open(const char *fname) {
    _trace_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
    _trace_writing = true;
}

void _trace_close(void) {
    if (_trace_if_count != 0) {
        _TRACE_NUM(_TRACE_SET_FUNC, 0);
        _TRACE_PUT(_trace_if_byte);
    }
    _trace_writing = false;
    close(_trace_fd);
}


// for retracing
int _retrace_fun_num;
bool _retrace_assert_values[256];
char _retrace_assert_label[256];

// only retrace.py should write in here
int _retrace_assert_index;

void _retrace_if(void) {}

void _retrace_else(void) {}

void _retrace_fun_call(void) {}

void _retrace_return(void) {}

void _retrace_assert_passed(void) {};

unsigned int _retrace_int;

void _retrace_wrote_int(void) {}

unsigned int _retrace_num(unsigned int num) {
    _retrace_int = num;
    _retrace_wrote_int();
    return num;
}

void _retrace_assert(char label[], _Bool a) {
    strcpy(_retrace_assert_label, label);
    _retrace_assert_passed();
    // Save the negation of the result (makes initialization simpler)
    _retrace_assert_values[_retrace_assert_index] = !a;
}
