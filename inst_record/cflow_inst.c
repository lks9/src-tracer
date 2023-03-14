#include "cflow_inst.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

int _trace_fd;
bool _trace_writing = false;

unsigned char _trace_if_byte;
int _trace_if_count;

void _trace_write(const void *buf, int count) {
    if (_trace_writing) {
        _trace_writing = false;
        write(_trace_fd, buf, count);
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
