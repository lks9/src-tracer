// src_tracer.h

// This file comes without any standard library include.
// Reason: It works on pre-processed files.
// A "#include <stdbool.h>" would result in double included files!

// editable constant definitions
#ifndef TRACE_BUF_SIZE
#define TRACE_BUF_SIZE 4096
#endif
#ifndef TRACE_USE_POSIX_WRITE
// if TRACE_USE_POSIX_WRITE is not set we use the syscall directly
#endif

// other constants
#define PROP_FALSE          0
#define PROP_TRUE           1
#define PROP_DEFAULT_VALUE  2


// and here comes the rest...
#ifdef __cplusplus
extern "C" {
#endif

// bool is available in C++ but not in C without (see above) include stdbool
#ifndef __cplusplus
#define bool _Bool
#endif

extern void _trace_open(const char *fname);
extern void _trace_close(void);

extern unsigned char _trace_if_byte;
extern int _trace_if_count;

extern char *_trace_ptr;
extern bool _trace_ptr_count;

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

#define _TRACE_PUT(c) ;{ \
    _trace_ptr[0] = (c); \
    _trace_ptr = &_trace_ptr[_trace_ptr_count]; \
}

#define _TRACE_PUT_TEXT     _TRACE_PUT

#define _TRACE_IE(if_true) ;{ \
    _trace_if_byte |= (if_true) << _trace_if_count; \
    _trace_if_count += 1; \
    if (_trace_if_count == 7) { \
        _TRACE_PUT(_trace_if_byte); \
        _trace_if_count = 0; \
        _trace_if_byte = _TRACE_SET_IE; \
    } \
}

#define _TRACE_NUM(type, num) ;{ \
    unsigned long long _trace_n = (num); \
    if (_trace_n == 0) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_0); \
    } else if (_trace_n == (_trace_n & 0xff)) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_8); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
    } else if (_trace_n == (_trace_n & 0xffff)) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_16); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
        _TRACE_PUT((_trace_n >> 8) & 0xff); \
    } else if (_trace_n == (_trace_n & 0xffffffff)) { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_32); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
        _TRACE_PUT((_trace_n >> 8) & 0xff); \
        _TRACE_PUT((_trace_n >> 16) & 0xff); \
        _TRACE_PUT((_trace_n >> 24) & 0xff); \
    } else { \
        _TRACE_PUT((type) | _trace_if_count | _TRACE_SET_LEN_64); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
        _TRACE_PUT((_trace_n >> 8) & 0xff); \
        _TRACE_PUT((_trace_n >> 16) & 0xff); \
        _TRACE_PUT((_trace_n >> 24) & 0xff); \
        _TRACE_PUT((_trace_n >> 32) & 0xff); \
        _TRACE_PUT((_trace_n >> 40) & 0xff); \
        _TRACE_PUT((_trace_n >> 48) & 0xff); \
        _TRACE_PUT((_trace_n >> 56) & 0xff); \
    } \
}

#define NIBBLE_TO_HEX_(n)   (((n) >= 0xa) ? (n) - 0xa + 'a' : (n) + '0')
#define NIBBLE_TO_HEX(n,i)  NIBBLE_TO_HEX_(((n) >> ((i)*4)) & 0xf)

// Shift twice, otherwise we might run into undefined behavior!
#define NIBBLE_COUNT(n,c)   (((n) >> (c)*3 >> (c)) != 0)

#define _TRACE_NUM_TEXT(type, num) ;{ \
    int count; \
    _TRACE_PUT(type); \
    for (count = 0; NIBBLE_COUNT((num), count); count++) {}  \
    for (int i = count-1; i >= 0; i--) { \
        _TRACE_PUT(NIBBLE_TO_HEX((num), i)); \
    } \
}

#define _TRACE_RETURN() \
    _TRACE_PUT(_TRACE_SET_RETURN | _trace_if_count)

// same as the macro version
// but returns num
// can be used inside switch conditions
static inline long long int _trace_num(char type, long long int num) {
    _TRACE_NUM(type, num);
    return num;
}

static inline long long int _trace_num_text(char type, long long int num) {
    _TRACE_NUM_TEXT(type, num);
    return num;
}

static inline long long int _trace_condition(long long int cond) {
    _TRACE_IE(cond);
    return cond;
}

static inline long long int _text_trace_condition(long long int cond) {
    if (cond) {
        _TRACE_PUT_TEXT('T');
    } else {
        _TRACE_PUT_TEXT('N');
    }
    return cond;
}


// for retracing
extern void _retrace_if(void);
extern void _retrace_else(void);

extern int _retrace_fun_num;
extern void _retrace_fun_call(void);
extern void _retrace_return(void);

extern long long int _retrace_int;
extern void _retrace_wrote_int(void);

#define _RETRACE_FUN_CALL(num) ;{ \
    _retrace_fun_num = (num); \
    _retrace_fun_call(); \
}

#define _RETRACE_NUM(num) ;{ \
    _retrace_int = (num); \
    _retrace_wrote_int(); \
}

static inline long long int _retrace_num(long long int num) {
    _retrace_int = num;
    _retrace_wrote_int();
    return num;
}

static inline long long int _retrace_condition(long long int cond) {
    if (cond) {
        _retrace_if();
    } else {
        _retrace_else();
    }
    return cond;
}

// for both tracing and retracing
extern bool _is_retrace_mode;

#define _IS_RETRACE(a,b)    ; \
    if (_is_retrace_mode) { \
        a; \
    } else { \
        b; \
    }

static inline long long int _is_retrace_condition(long long int cond) {
    if (cond) {
        _IS_RETRACE(_retrace_if(), _TRACE_IE(1));
    } else {
        _IS_RETRACE(_retrace_else(), _TRACE_IE(0));
    }
    return cond;
}

/* This can be used for switch:
 *    switch(        num ) { ... }
 * Annotated:
 *    switch(_SWITCH(num)) { ... }
 * The makro _SWITCH might translate to _is_retrace_switch.
 */
static inline long long int _is_retrace_switch(long long int num) {
    _IS_RETRACE(_RETRACE_NUM(num),
                _TRACE_NUM(_TRACE_SET_DATA, num)
    )
    return num;
}

/*
 * Macros used in the instrumentation.
 * 2 versions: _TRACE_MODE and _RETRACE_MODE
 */

#if defined _TRACE_MODE && defined _RETRACE_MODE
/* combined trace/retrace mode, experimental */

#define _IF                 _IS_RETRACE(_retrace_if(), _TRACE_IE(1))
#define _ELSE               _IS_RETRACE(_retrace_else(), _TRACE_IE(0))
#define _CONDITION(cond)    _is_retrace_condition((long long int)(cond))
#define _FUNC(num)          _IS_RETRACE(_RETRACE_FUN_CALL((num)), _TRACE_NUM(_TRACE_SET_FUNC, (num)))
#define _FUNC_RETURN        _IS_RETRACE(_retrace_return(), _TRACE_RETURN())
// non-macro version for switch
#define _SWITCH(num)        _is_retrace_switch((num))
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _IS_RETRACE(_RETRACE_NUM(num), _TRACE_NUM(_TRACE_SET_DATA, num)) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _IS_RETRACE(_retrace_if(), _TRACE_IE(1))
#define _LOOP_END(id)       _IS_RETRACE(_retrace_else(), _TRACE_IE(0))

#define _TRACE_OPEN(fname)  _IS_RETRACE( ,_trace_open((fname)))
#define _TRACE_CLOSE        _IS_RETRACE( ,_trace_close())

#define _GHOST(code)        code


#elif defined _TRACE_MODE
/* trace mode */

#define _IF                 _TRACE_IE(1)
#define _ELSE               _TRACE_IE(0)
#define _CONDITION(cond)    _trace_condition((long long int)(cond))
#define _FUNC(num)          _TRACE_NUM(_TRACE_SET_FUNC, (num))
#define _FUNC_RETURN        _TRACE_RETURN()
// non-macro version for switch
#define _SWITCH(num)        _trace_num(_TRACE_SET_DATA, (num))
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _TRACE_NUM(_TRACE_SET_DATA, num) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _TRACE_IE(1)
#define _LOOP_END(id)       _TRACE_IE(0)

#define _TRACE_OPEN(fname)  ;_trace_open((fname));
#define _TRACE_CLOSE        ;_trace_close();

#define _GHOST(code)        /* nothing here */


#elif defined _TEXT_TRACE_MODE
/* text trace mode, experimental */

#define _IF                 ;_TRACE_PUT_TEXT('T');
#define _ELSE               ;_TRACE_PUT_TEXT('N');
#define _CONDITION(cond)    _text_trace_condition((unsigned int)cond)
#define _FUNC(num)          ;_TRACE_NUM_TEXT('F', ((unsigned int)num));
#define _FUNC_RETURN        ;_TRACE_PUT_TEXT('R');
// non-macro version for switch
#define _SWITCH(num)        _trace_num_text('D', ((unsigned int)num))
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _TRACE_NUM_TEXT('D', ((unsigned int)num)); \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_TRACE_PUT_TEXT('T');
#define _LOOP_END(id)       ;_TRACE_PUT_TEXT('N');

#define _TRACE_OPEN(fname)  ;_trace_open(fname ".txt");
#define _TRACE_CLOSE        ;_trace_close();

#define _GHOST(code)        /* nothing here */


#elif defined _RETRACE_MODE
/* retrace mode */

#define _IF                 ;_retrace_if();
#define _ELSE               ;_retrace_else();
#define _CONDITION(cond)    _retrace_condition((long long int)(cond))
#define _FUNC(num)          _RETRACE_FUN_CALL(num)
#define _FUNC_RETURN        ;_retrace_return();
// non-macro version for switch
#define _SWITCH(num)        _retrace_num(num)
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _RETRACE_NUM(num) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_retrace_if();
#define _LOOP_END(id)       ;_retrace_else();

#define _TRACE_OPEN(fname)  /* nothing here */
#define _TRACE_CLOSE        /* nothing here */

#define _GHOST(code)        code


#else // neither _TRACE_MODE nor _RETRACE_MODE

#define _IF                 /* nothing here */
#define _ELSE               /* nothing here */
#define _CONDITION(cond)    cond
#define _FUNC(num)          /* nothing here */
#define _FUNC_RETURN        /* nothing here */
#define _SWITCH(num)        num
#define _SWITCH_START(id)   /* nothing here */
#define _CASE(num, id)      /* nothing here */
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      /* nothing here */
#define _LOOP_END(id)       /* nothing here */

#define _TRACE_OPEN(fname)  /* nothing here */
#define _TRACE_CLOSE        /* nothing here */

#define _GHOST(code)        /* nothing here */

#endif // _TRACE_MODE or _RETRACE_MODE

#ifdef __cplusplus
} // end extern "C"
#endif
