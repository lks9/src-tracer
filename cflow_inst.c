#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>

#include "cflow_inst.h"

#define _CFLOW_NO_RECORD

char _cflow_tmpstr[18];
int _cflow_put_count = 0;
#ifndef _CFLOW_NO_RECORD
int _cflow_fd;
#endif

void _cflow_put(char c) {
    _cflow_tmpstr[0] = c;
    _cflow_tmpstr[1] = '\0';
#ifndef _CFLOW_NO_RECORD
    write(_cflow_fd, _cflow_tmpstr, 1);
#endif
    _cflow_put_count += 1;
}

void _cflow_put_num(char c, int num) {
    _cflow_tmpstr[0] = c;
    int tmpstr_len = 1 + snprintf(&_cflow_tmpstr[1], 17, "%x", num);
#ifndef _CFLOW_NO_RECORD
    write(_cflow_fd, _cflow_tmpstr, tmpstr_len);
#endif
    _cflow_put_count += 1;
}

void _cflow_open(char *fname) {
#ifndef _CFLOW_NO_RECORD
    _cflow_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
}

void _cflow_close(void) {
#ifndef _CFLOW_NO_RECORD
    write(_cflow_fd, "\n", 1);
    close(_cflow_fd);
#endif
}
