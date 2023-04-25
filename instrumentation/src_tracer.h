extern void _trace_write(const void* buf, int count);

extern void _trace_open(const char *fname);
extern void _trace_close(void);

extern unsigned char _trace_if_byte;
extern int _trace_if_count;

#define _TRACE_BUF_SIZE     4096
extern unsigned char _trace_buf[_TRACE_BUF_SIZE];
extern int _trace_buf_pos;

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
    _trace_buf[_trace_buf_pos] = c; \
    _trace_buf_pos += 1; \
    if (_trace_buf_pos == _TRACE_BUF_SIZE) { \
        _trace_write(_trace_buf, _TRACE_BUF_SIZE); \
        _trace_buf_pos = 0; \
    }

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
    if (n == 0) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_0); \
    } else if (n == (n & 0xff)) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_8); \
        _TRACE_PUT((n >> 0) & 0xff); \
    } else if (n == (n & 0xffff)) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_16); \
        _TRACE_PUT((n >> 0) & 0xff); \
        _TRACE_PUT((n >> 8) & 0xff); \
    } else if (n == (n & 0xffffffff)) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_32); \
        _TRACE_PUT((n >> 0) & 0xff); \
        _TRACE_PUT((n >> 8) & 0xff); \
        _TRACE_PUT((n >> 16) & 0xff); \
        _TRACE_PUT((n >> 24) & 0xff); \
    } else { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_64); \
        _TRACE_PUT((n >> 0) & 0xff); \
        _TRACE_PUT((n >> 8) & 0xff); \
        _TRACE_PUT((n >> 16) & 0xff); \
        _TRACE_PUT((n >> 24) & 0xff); \
        _TRACE_PUT((n >> 32) & 0xff); \
        _TRACE_PUT((n >> 40) & 0xff); \
        _TRACE_PUT((n >> 48) & 0xff); \
        _TRACE_PUT((n >> 56) & 0xff); \
    } \
}

#define NIBBLE_TO_HEX_(n)   (((n) >= 0xa) ? (n) - 0xa + 'a' : (n) + '0')
#define NIBBLE_TO_HEX(n,i)  NIBBLE_TO_HEX_(((n) >> ((i)*4)) & 0xf)

// Shift twice, otherwise we might run into undefined behavior!
#define NIBBLE_COUNT(n,c)   (((n) >> (c)*3 >> (c)) != 0)

#define _TRACE_NUM_TEXT(type, num) ;{ \
    unsigned char buf[18]; \
    int count; \
    buf[0] = type; \
    for (count = 0; NIBBLE_COUNT(num, count); count++) {}  \
    for (int i = 0; i < count; i++) { \
        buf[count-i] = NIBBLE_TO_HEX(num, i); \
    } \
    _trace_write(buf, 1+count); \
}

#define _TRACE_RETURN() \
    _TRACE_PUT(_TRACE_SET_RETURN | _trace_if_count)

// same as the macro version
// but returns num
// can be used inside switch conditions
extern unsigned int _trace_num(char c, unsigned int num);
extern unsigned int _trace_num_text(char c, unsigned int num);
extern _Bool _trace_condition(_Bool cond);

// for retracing
extern void _retrace_if(void);
extern void _retrace_else(void);
extern _Bool _retrace_condition(_Bool cond);
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
extern _Bool _is_retrace_condition(_Bool cond);

#define _IF                 _IS_RETRACE(_retrace_if(), _TRACE_IE(1))
#define _ELSE               _IS_RETRACE(_retrace_else(), _TRACE_IE(0))
#define _CONDITION(cond)    _is_retrace_condition(cond)
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
#define _CONDITION(cond)    _trace_condition(cond)
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

#define _IF                 ;_TRACE_PUT_('T');
#define _ELSE               ;_TRACE_PUT_('N');
#define _CONDITION(cond)    _text_trace_condition(cond)
#define _FUNC(num)          ;_TRACE_NUM_TEXT('F', ((unsigned int)num));
#define _FUNC_RETURN        ;_TRACE_PUT_('R');
// non-macro version for switch
#define _SWITCH(num)        _trace_num_text('D', ((unsigned int)num))
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
#define _CONDITION(cond)    _retrace_condition(cond)
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
#define _CONDITION(cond)    cond
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
