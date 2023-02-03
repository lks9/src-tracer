extern void _cflow_if(void);
extern void _cflow_else(void);
extern void _cflow_wrote_int(void);
extern unsigned int _cflow_put_num(unsigned int num);

#define _FUNC(num)          ;
#define _IF                 ;_cflow_if();
#define _ELSE               ;_cflow_else();
#define _SWITCH(num)        _cflow_put_num(num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_cflow_if();
#define _LOOP_END(id)       ;_cflow_else();

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    int retval = main_original(argc, argv); \
    return retval; \
}
