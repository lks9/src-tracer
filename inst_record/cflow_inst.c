#include "cflow_inst.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

int _cflow_fd;
bool _cflow_writing = false;

unsigned char _cflow_if_byte;
int _cflow_if_count;

void _cflow_write(const void *buf, int count) {
    if (_cflow_writing) {
        _cflow_writing = false;
        write(_cflow_fd, buf, count);
        _cflow_writing = true;
    }
}

// same as the macro version
// but returns num
// can be used inside switch conditions
unsigned int _cflow_put_num(char type, unsigned int num) {
    _CFLOW_PUT_NUM(type, num)
    return num;
}

void _cflow_open(const char *fname) {
    _cflow_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    _cflow_if_count = 0;
    _cflow_if_byte = _PUT_IE;
    _cflow_writing = true;
}

void _cflow_close(void) {
    if (_cflow_if_count != 0) {
        _CFLOW_PUT_NUM(_PUT_FUNC, 0);
        _CFLOW_PUT(_cflow_if_byte);
    }
    _cflow_writing = false;
    close(_cflow_fd);
}
