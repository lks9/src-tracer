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

struct _trace_ctx {
    char *ptr;
    char *_page_ptr;
    int fd;
    int fork_count;
    int try_count;
    bool active;
};

#define _TRACE_IF_BYTE_INIT       ((1 << 14))
register short int _trace_if_byte __asm__ ("r12");

extern struct _trace_ctx _trace;

extern void _trace_open(const char *fname);
extern void _trace_close(void);
extern void _trace_before_fork(void);
extern int _trace_after_fork(int pid);

#define _TRACE_TEST_IE            0b10000000
 #define _TRACE_SET_IE            0b10000000

#define _TRACE_TEST_FUNC_DATA     0b10001000
 #define _TRACE_SET_FUNC          0b00000000
 #define _TRACE_SET_DATA          0b00001000

#define _TRACE_TEST_LEN           0b11111000
 #define _TRACE_SET_LEN_0         0b00001000
 #define _TRACE_SET_LEN_8         0b00011000
 #define _TRACE_SET_LEN_16        0b00101000
 #define _TRACE_SET_LEN_32        0b00111000
 #define _TRACE_SET_LEN_64        0b01001000
 #define _TRACE_SET_LEN_reserved  0b01011000
 #define _TRACE_SET_LEN_PREFIX    0b01101000
 #define _TRACE_SET_LEN_STRING    0b01110000

 #define _TRACE_SET_FUNC_END      0b00000000
 #define _TRACE_SET_FUNC_LEN_0    0b00000000
 #define _TRACE_SET_FUNC_LEN_8    0b00010000
 #define _TRACE_SET_FUNC_LEN_16   0b00100000
 #define _TRACE_SET_FUNC_LEN_32   0b00110000
 #define _TRACE_SET_FUNC_LEN_24   0b01000000
 #define _TRACE_SET_FUNC_RETURN   0b01010000
 #define _TRACE_SET_FUNC_ANON     0b01100000
 #define _TRACE_SET_FUNC_reserved 0b01110000

#define _TRACE_TEST_IE_COUNT      0b10000111

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define _TRACE_PUT(c) ; \
    if (_trace.active) { \
        _trace.ptr[0] = (c); \
        _trace.ptr += 1; \
    }

#define _TRACE_PUT_TEXT     _TRACE_PUT

#define _TRACE_IE(if_true) ;{ \
        _trace_if_byte >>= 1; \
        _trace_if_byte |= ((short)(if_true)) << 6; \
        if (_trace_if_byte & (1 << 7)) { \
            _TRACE_PUT((char)(_trace_if_byte)); \
            _trace_if_byte = _TRACE_IF_BYTE_INIT; \
        } \
    }

#define _SHIFT_TO_NUM(shift) \
    ( ((shift & 0b0010101010000000) ? 1 : 0) \
    | ((shift & 0b0001100110000000) ? 2 : 0) \
    | ((shift & 0b0000011110000000) ? 4 : 0) \
    )

#define _IF_COUNT \
    _SHIFT_TO_NUM(_trace_if_byte)

#define _TRACE_FUNC(num) ;{ \
    if ((num) == 0) { \
        _TRACE_PUT(_TRACE_SET_FUNC | _IF_COUNT | _TRACE_SET_FUNC_ANON); \
    } else if ((num) == ((num) & 0xff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC | _IF_COUNT | _TRACE_SET_FUNC_LEN_8); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
    } else if ((num) == ((num) & 0xffff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC | _IF_COUNT | _TRACE_SET_FUNC_LEN_16); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
        _TRACE_PUT(((num) >> 8) & 0xff); \
    } else if ((num) == ((num) & 0xffffff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC | _IF_COUNT | _TRACE_SET_FUNC_LEN_24); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
        _TRACE_PUT(((num) >> 8) & 0xff); \
        _TRACE_PUT(((num) >> 16) & 0xff); \
    } else if ((num) == ((num) & 0xffffffff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC | _IF_COUNT | _TRACE_SET_FUNC_LEN_32); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
        _TRACE_PUT(((num) >> 8) & 0xff); \
        _TRACE_PUT(((num) >> 16) & 0xff); \
        _TRACE_PUT(((num) >> 24) & 0xff); \
    } \
}

#define _TRACE_NUM(num) ;{ \
    unsigned long long _trace_n = (num); \
    if (_trace_n == 0) { \
        _TRACE_PUT(_TRACE_SET_DATA | _IF_COUNT | _TRACE_SET_LEN_0); \
    } else if (_trace_n == (_trace_n & 0xff)) { \
        _TRACE_PUT(_TRACE_SET_DATA | _IF_COUNT | _TRACE_SET_LEN_8); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
    } else if (_trace_n == (_trace_n & 0xffff)) { \
        _TRACE_PUT(_TRACE_SET_DATA | _IF_COUNT | _TRACE_SET_LEN_16); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
        _TRACE_PUT((_trace_n >> 8) & 0xff); \
    } else if (_trace_n == (_trace_n & 0xffffffff)) { \
        _TRACE_PUT(_TRACE_SET_DATA | _IF_COUNT | _TRACE_SET_LEN_32); \
        _TRACE_PUT((_trace_n >> 0) & 0xff); \
        _TRACE_PUT((_trace_n >> 8) & 0xff); \
        _TRACE_PUT((_trace_n >> 16) & 0xff); \
        _TRACE_PUT((_trace_n >> 24) & 0xff); \
    } else { \
        _TRACE_PUT(_TRACE_SET_DATA | _IF_COUNT | _TRACE_SET_LEN_64); \
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
    _TRACE_PUT(_TRACE_SET_FUNC_RETURN | _IF_COUNT)

#define _TRACE_END() \
    _TRACE_PUT(_TRACE_SET_FUNC_END | _IF_COUNT)

// same as the macro version
// but returns num
// can be used inside switch conditions
static inline __attribute__((always_inline)) long long int _trace_num(long long int num) {
    _TRACE_NUM(num);
    return num;
}

static inline __attribute__((always_inline)) long long int _trace_num_text(char type, long long int num) {
    _TRACE_NUM_TEXT(type, num);
    return num;
}

static inline __attribute__((always_inline)) bool _trace_condition(bool cond) {
    _TRACE_IE(cond);
    return cond;
}

static inline __attribute__((always_inline)) bool _text_trace_condition(bool cond) {
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

extern volatile int _retrace_fun_num;
extern void _retrace_fun_call(void);
extern void _retrace_return(void);

extern volatile long long int _retrace_int;
extern void _retrace_wrote_int(void);

extern volatile int _retrace_fork_count;

#define _RETRACE_FUN_CALL(num) ;{ \
    _retrace_fun_num = (num); \
    _retrace_fun_call(); \
}

#define _RETRACE_NUM(num) ;{ \
    _retrace_int = (num); \
    _retrace_wrote_int(); \
}

static inline __attribute__((always_inline)) long long int _retrace_num(long long int num) {
    _retrace_int = num;
    _retrace_wrote_int();
    return num;
}

static inline __attribute__((always_inline)) bool _retrace_condition(bool cond) {
    if (cond) {
        _retrace_if();
    } else {
        _retrace_else();
    }
    return cond;
}

// for both tracing and retracing
extern volatile bool _is_retrace_mode;

#define _IS_RETRACE(a,b)    ; \
    if (_is_retrace_mode) { \
        a; \
    } else { \
        b; \
    }

static inline __attribute__((always_inline)) bool _is_retrace_condition(bool cond) {
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
static inline __attribute__((always_inline)) long long int _is_retrace_switch(long long int num) {
    _IS_RETRACE(_RETRACE_NUM(num),
                _TRACE_NUM(num)
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
#define _CONDITION(cond)    _is_retrace_condition(cond)
#define _FUNC(num)          _IS_RETRACE(_RETRACE_FUN_CALL(num), _TRACE_FUNC(num))
#define _FUNC_RETURN        _IS_RETRACE(_retrace_return(), _TRACE_RETURN())
// non-macro version for switch
#define _SWITCH(num)        _is_retrace_switch(num)
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _IS_RETRACE(_RETRACE_NUM(num), _TRACE_NUM(num)) \
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
#define _CONDITION(cond)    _trace_condition(cond)
#define _FUNC(num)          _TRACE_FUNC(num)
#define _FUNC_RETURN        _TRACE_RETURN()
// non-macro version for switch
#define _SWITCH(num)        _trace_num(num)
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _TRACE_NUM(num) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _TRACE_IE(1)
#define _LOOP_END(id)       _TRACE_IE(0)

#define _TRACE_OPEN(fname)  ;_trace_open((fname));
#define _TRACE_CLOSE        ;_trace_close();

#define _FORK(fork_stmt)    (_trace_before_fork(), \
                             _trace_after_fork(fork_stmt))

#define _GHOST(code)        /* nothing here */


#elif defined _TEXT_TRACE_MODE
/* text trace mode, experimental */

#define _IF                 ;_TRACE_PUT_TEXT('T');
#define _ELSE               ;_TRACE_PUT_TEXT('N');
#define _CONDITION(cond)    _text_trace_condition(cond)
#define _FUNC(num)          ;_TRACE_NUM_TEXT('F', ((unsigned int)(num)));
#define _FUNC_RETURN        ;_TRACE_PUT_TEXT('R');
// non-macro version for switch
#define _SWITCH(num)        _trace_num_text('D', ((unsigned int)(num)))
// experimental version for switch
#define _SWITCH_START(id)   ;bool _cflow_switch_##id = 1;
#define _CASE(num, id)      ;if (_cflow_switch_##id) { \
                                _TRACE_NUM_TEXT('D', ((unsigned int)(num))); \
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
#define _CONDITION(cond)    _retrace_condition(cond)
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

#define _FORK(fork_stmt)    (_retrace_num(_retrace_fork_count), \
                             _retrace_num((fork_stmt) < 0 ? -1 : 1))

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

#define _FORK(fork_stmt)    fork_stmt

#define _GHOST(code)        /* nothing here */

#endif // _TRACE_MODE or _RETRACE_MODE

#ifdef __cplusplus
} // end extern "C"
#endif
