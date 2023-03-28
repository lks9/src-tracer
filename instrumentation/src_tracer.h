extern void _trace_write(const void* buf, int count);

extern void _trace_open(const char *fname);
extern void _trace_close(void);

extern int _trace_if_count;
extern unsigned char _trace_if_byte;

#define _TRACE_TEST_IE            0b10000000
 #define _TRACE_SET_IE            0b10000000
#define _TRACE_TEST_FUNC          0b10001000
 #define _TRACE_SET_FUNC          0b00000000
#define _TRACE_TEST_DATA          0b10001000
 #define _TRACE_SET_DATA          0b00001000
#define _TRACE_TEST_LEN           0b11110000
 #define _TRACE_SET_LEN_0         0b00000000
 #define _TRACE_SET_LEN_8         0b00010000
 #define _TRACE_SET_LEN_16        0b00100000
 #define _TRACE_SET_LEN_32        0b00110000
 #define _TRACE_SET_LEN_64        0b01000000
 #define _TRACE_SET_LEN_reserved  0b01010000
 #define _TRACE_SET_LEN_PREFIX    0b01100000
 #define _TRACE_SET_LEN_STRING    0b01110000
#define _TRACE_TEST_RETURN        0b11111000
 #define _TRACE_SET_RETURN        0b01010000
#define _TRACE_TEST_IE_COUNT      0b10000111

#define _TRACE_PUT(c) \
    _trace_write(&c, 1)

#define _TRACE_PUT_(c) ;{ \
    unsigned char buf[1] = { c }; \
    _trace_write(buf, 1); \
}

#define _TRACE_IE(if_true) ;{ \
    _trace_if_byte |= if_true << _trace_if_count; \
    _trace_if_count += 1; \
    if (_trace_if_count == 7) { \
        _TRACE_PUT(_trace_if_byte); \
        _trace_if_count = 0; \
        _trace_if_byte = _TRACE_SET_IE; \
    } \
}

#define _TRACE_NUM(type, num) ;{ \
    unsigned long long n = num; \
    int count; \
    unsigned char buf[9]; \
    buf[0] = type; \
    buf[0] |= _trace_if_count; \
    if (n == 0) { \
        buf[0] |= _TRACE_SET_LEN_0; \
        count = 0; \
    } else if (n == (n & 0xff)) { \
        buf[0] |= _TRACE_SET_LEN_8; \
        count = 1; \
    } else if (n == (n & 0xffff)) { \
        buf[0] |= _TRACE_SET_LEN_16; \
        count = 2; \
    } else if (n == (n & 0xffffffff)) { \
        buf[0] |= _TRACE_SET_LEN_32; \
        count = 4; \
    } else { \
        buf[0] |= _TRACE_SET_LEN_64; \
        count = 8; \
    } \
    buf[1] = (n >> 0) & 0xff; \
    buf[2] = (n >> 8) & 0xff; \
    buf[3] = (n >> 16) & 0xff; \
    buf[4] = (n >> 24) & 0xff; \
    buf[5] = (n >> 32) & 0xff; \
    buf[6] = (n >> 40) & 0xff; \
    buf[7] = (n >> 48) & 0xff; \
    buf[8] = (n >> 56) & 0xff; \
    _trace_write(buf, count+1); \
}

#define _TRACE_RETURN() \
    _TRACE_PUT_(_TRACE_SET_RETURN | _trace_if_count)


// same as the macro version
// but returns num
// can be used inside switch conditions
extern unsigned int _trace_num(char c, unsigned int num);


// for retracing
extern void _retrace_if(void);
extern void _retrace_else(void);
extern void _retrace_fun_call(void);
extern void _retrace_return(void);
extern void _retrace_assert(char label[], _Bool a);
extern unsigned int _retrace_num(unsigned int num);

extern int _retrace_fun_num;
extern char _retrace_assert_label[256];

#define _RETRACE_FUN_CALL(num) ;{ \
    _retrace_fun_num = num; \
    _retrace_fun_call(); \
}

#define _RETRACE_NUM(num) ;{ \
    _retrace_int = num; \
    _retrace_wrote_int(); \
}

#define _IS_RETRACE(a,b)    ; \
    if (_is_retrace_mode) { \
        a; \
    } else { \
        b; \
    }

/*
 * Macros used in the instrumentation.
 * 2 versions: _TRACE_MODE and _RETRACE_MODE
 */

#if defined _TRACE_MODE && defined _RETRACE_MODE
/* both */

extern _Bool _is_retrace_mode;
extern unsigned int _is_retrace_switch(unsigned int num);

#define _IF                 _IS_RETRACE(_retrace_if(), _TRACE_IE(1))
#define _ELSE               _IS_RETRACE(_retrace_else(), _TRACE_IE(0))
#define _FUNC(num)          _IS_RETRACE(_RETRACE_FUN_CALL(num), _TRACE_NUM(_TRACE_SET_FUNC, num))
#define _FUNC_RETURN        _IS_RETRACE(_retrace_return(), _TRACE_RETURN())
// non-macro version for switch
#define _SWITCH(num)        _is_retrace_switch(num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _IS_RETRACE(_retrace_if(), _TRACE_IE(1))
#define _LOOP_END(id)       _IS_RETRACE(_retrace_else(), _TRACE_IE(0))

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    _trace_open(fname); \
    int retval = main_original(argc, argv); \
    _trace_close(); \
    return retval; \
}

#elif defined _TRACE_MODE

#define _IF                 _TRACE_IE(1)
#define _ELSE               _TRACE_IE(0)
#define _FUNC(num)          _TRACE_NUM(_TRACE_SET_FUNC, num)
#define _FUNC_RETURN        _TRACE_RETURN()
// non-macro version for switch
#define _SWITCH(num)        _trace_num(_TRACE_SET_DATA, num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _TRACE_IE(1)
#define _LOOP_END(id)       _TRACE_IE(0)

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    _trace_open(fname); \
    int retval = main_original(argc, argv); \
    _trace_close(); \
    return retval; \
}

#define _RETRACE_ASSERT(l,a)  /* nothing here */

#elif defined _TEXT_TRACE_MODE /* TODO, use _TRACE_MODE instead */

#define _TEXT_TRACE_FUNC(num) ;{ \
    char num_str[] = #num; \
    _TRACE_PUT_('F'); \
    for (char *ptr = &num_str[2]; *ptr != '\0'; ptr = &ptr[1]) { \
        _TRACE_PUT(*ptr); \
    } \
}

int _text_trace_switch(int num, char *num_str);

#define _TEXT_TRACE_SWITCH(num) \
    _text_trace_switch(num, #num)

#define _IF                 ;_TRACE_PUT_('T');
#define _ELSE               ;_TRACE_PUT_('N');
#define _FUNC(num)          _TEXT_TRACE_FUNC(num)
#define _FUNC_RETURN        ;_TRACE_PUT_('R');
// non-macro version for switch
#define _SWITCH(num)        _TEXT_TRACE_SWITCH(num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_TRACE_PUT_('T');
#define _LOOP_END(id)       ;_TRACE_PUT_('N');

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    _trace_open(fname ".txt"); \
    int retval = main_original(argc, argv); \
    _trace_close(); \
    return retval; \
}

#define _RETRACE_ASSERT(l,a)  /* nothing here */

#elif defined _RETRACE_MODE

#define _IF                 ;_retrace_if();
#define _ELSE               ;_retrace_else();
#define _FUNC(num)          _RETRACE_FUN_CALL(num)
#define _FUNC_RETURN        ;_retrace_return();
#define _SWITCH(num)        _retrace_num(num)
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_retrace_if();
#define _LOOP_END(id)       ;_retrace_else();

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    int retval = main_original(argc, argv); \
    return retval; \
}

#define _RETRACE_ASSERT(label, a) \
                            _retrace_assert(label, a);

#else // neither _TRACE_MODE nor _RETRACE_MODE

#define _IF                 /* nothing here */
#define _ELSE               /* nothing here */
#define _FUNC(num)          /* nothing here */
#define _FUNC_RETURN        /* nothing here */
#define _SWITCH(num)        num
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      /* nothing here */
#define _LOOP_END(id)       /* nothing here */

#define _MAIN_FUN(fname)    \
int main (int argc, char **argv) { \
    int retval = main_original(argc, argv); \
    return retval; \
}

#define _RETRACE_ASSERT(l,a)  /* nothing here */

#endif // _TRACE_MODE or _RETRACE_MODE
