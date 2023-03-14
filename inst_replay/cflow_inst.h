extern void _retrace_if(void);
extern void _retrace_else(void);
extern unsigned int _retrace_num(unsigned int num);

#define _FUNC(num)          ;
#define _IF                 ;_retrace_if();
#define _ELSE               ;_retrace_else();
#define _SWITCH(num)        _retrace_put_num(num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_retrace_if();
#define _LOOP_END(id)       ;_retrace_else();

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    int retval = main_original(argc, argv); \
    return retval; \
}
