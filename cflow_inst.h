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
#define _FUNC_INST(i)       _cflow_put_num('F', i);
#define _IF_INST            _cflow_put('I');
#define _ELSE_INST          _cflow_put('E');
#define _SWITCH_INST(i)     _cflow_put_num('S', i);
#define _LOOP_START(id)     int _cflow_counter_##id = 0; \
                            _cflow_put('L');
#define _LOOP_BODY(id)      _cflow_counter_##id ++;
#define _LOOP_END(id)       _cflow_put_num('P', _cflow_counter_##id);
