extern void _cflow_put(char c);
extern int _cflow_put_num(char c, int num);

extern void _cflow_open(const char *fname);
extern void _cflow_close(void);

#define _FUNC(num)          ;_cflow_put_num('F', num);
#define _IF                 ;_cflow_put('I');
#define _ELSE               ;_cflow_put('E');
// use it like "switch(_SWITCH(i)) { ... }"
#define _SWITCH(num)        _cflow_put_num('S', num)
// _SWITCH_START() + _CASE() do the same as _SWITCH(), use either!
#define _SWITCH_START(id)   ;_Bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _cflow_put_num('S', num); \
                                _cflow_switch_##id = 0; \
                            }
#define _LOOP_START(id)     ;int _cflow_loopcount_##id = 0; \
                            _cflow_put('L');
#define _LOOP_BODY(id)      ;_cflow_loopcount_##id ++;
#define _LOOP_END(id)       ;_cflow_put_num('P', _cflow_loopcount_##id);

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    _cflow_open(fname); \
    int retval = main_original(argc, argv); \
    _cflow_close(); \
    return retval; \
}
