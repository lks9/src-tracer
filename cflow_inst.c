#include "cflow_inst.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

char _cflow_tmpstr[18];
int _cflow_put_count = 0;
#ifndef _CFLOW_NO_RECORD
int _cflow_fd;
#endif
bool _cflow_writing = false;

void _cflow_put(char c) {
    if (_cflow_writing) {
        _cflow_writing = false;
        _cflow_tmpstr[0] = c;
        _cflow_tmpstr[1] = '\0';
#ifndef _CFLOW_NO_RECORD
        write(_cflow_fd, _cflow_tmpstr, 1);
#endif
        _cflow_put_count += 1;
        _cflow_writing = true;
    }
}

int _cflow_put_num(char c, int num) {
    if (_cflow_writing) {
        _cflow_writing = false;
        _cflow_tmpstr[0] = c;
        int tmpstr_len = 1 + snprintf(&_cflow_tmpstr[1], 17, "%x", num);
#ifndef _CFLOW_NO_RECORD
        write(_cflow_fd, _cflow_tmpstr, tmpstr_len);
#endif
        _cflow_put_count += 1;
        _cflow_writing = true;
    }
    return num;
}

void _cflow_open(const char *fname) {
#ifndef _CFLOW_NO_RECORD
    _cflow_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
    _cflow_writing = true;
}

void _cflow_close(void) {
    _cflow_writing = false;
#ifndef _CFLOW_NO_RECORD
    write(_cflow_fd, "\n", 1);
    close(_cflow_fd);
#endif
}
