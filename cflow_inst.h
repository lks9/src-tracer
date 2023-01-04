#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>

char _cflow_tmpstr[17];
int _cflow_tmpstr_count;
int _cflow_fd;

#define _cflow_put(c)       _cflow_tmpstr[0] = c; \
                            write(_cflow_fd, _cflow_tmpstr, 1);
#define _cflow_put_num(c,i) _cflow_tmpstr[0] = c; \
                            _cflow_tmpstr_count = snprintf(&_cflow_tmpstr[1], 16, "%x", i); \
                            write(_cflow_fd, _cflow_tmpstr, _cflow_tmpstr_count + 1);
#define _CFLOW_INIT(fname)  _cflow_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC);
#define _CFLOW_CLEANUP      close(_cflow_fd);
#define _FUNC_INST(i)       _cflow_put_num('C', i);
#define _IF_INST            _cflow_put('I');
#define _ELSE_INST          _cflow_put('E');
#define _SWITCH_INST(i)     _cflow_put_num('S', i);
#define _LOOP_START(i)      int _cflow_##i = 0; \
                            _cflow_put('L');
#define _LOOP_BODY(i)       _cflow_##i ++;
#define _LOOP_END(i)        _cflow_put_num('P', _cflow_##i);

// effectless
#define _FUNC_END           ;
#define _IE_BLOCK_INST      ;
#define _IE_BLOCK_END       ;
#define _IFELSE_END         ;
