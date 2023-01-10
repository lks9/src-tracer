#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

extern void _cflow_put(char c);
extern void _cflow_put_num(char c, int num);

extern void _cflow_open(char *fname);
extern void _cflow_close();

#define _FUNC(num)          ;_cflow_put_num('F', num);
#define _IF                 ;_cflow_put('I');
#define _ELSE               ;_cflow_put('E');
#define _SWITCH(num)        ;_cflow_put_num('S', num);
// _SWITCH_START() + _CASE() do the same as _SWITCH(), while annotation is simpler
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = true;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _cflow_put_num('S', num); \
                                _cflow_switch_##id = false; \
                            };
#define _LOOP_START(id)     ;int _cflow_loopcount_##id = 0; \
                            ;_cflow_put('L');
#define _LOOP_BODY(id)      ;_cflow_loopcount_##id ++;
#define _LOOP_END(id)       ;_cflow_put_num('P', _cflow_loopcount_##id);
