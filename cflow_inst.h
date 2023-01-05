#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>

extern void _cflow_put(char c);
extern void _cflow_put_num(char c, int num);

extern void _cflow_open(char *fname);
extern void _cflow_close();

#define _FUNC(num)          _cflow_put_num('F', num);
#define _IF                 _cflow_put('I');
#define _ELSE               _cflow_put('E');
#define _SWITCH(num)        _cflow_put_num('S', num);
#define _LOOP_START(id)     int _cflow_counter_##id = 0; \
                            _cflow_put('L');
#define _LOOP_BODY(id)      _cflow_counter_##id ++;
#define _LOOP_END(id)       _cflow_put_num('P', _cflow_counter_##id);
