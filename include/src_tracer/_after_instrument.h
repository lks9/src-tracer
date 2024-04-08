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
#ifndef EFFICIENT_TEXT_TRACE
// well it's not for efficiency, more for debugging
#endif
// assumes short is 16 bit
// assumes char is 8 bit

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
#ifndef bool
#define bool _Bool
#endif
#endif

extern void _trace_write(const void *buf);
#ifndef EFFICIENT_TEXT_TRACE
extern void _trace_write_text(const void *buf, unsigned long count);
#endif

extern void _trace_open(const char *fname);
extern void _trace_close(void);
extern void _trace_before_fork(void);
extern int _trace_after_fork(int pid);

extern unsigned long long int _trace_setjmp_idx;

#ifndef BYTE_TRACE
#define _TRACE_IE_BYTE_INIT         0b11111110
extern unsigned char _trace_ie_byte;
#endif

extern unsigned char _trace_buf[TRACE_BUF_SIZE];
extern int _trace_buf_pos;

#define _TRACE_TEST_IE              0b10000000
 #define _TRACE_SET_IE              0b10000000

#define _TRACE_TEST_OTHER           0b11110000
 #define _TRACE_SET_FUNC_4          0b00000000
 #define _TRACE_SET_FUNC_12         0b00010000
 #define _TRACE_SET_FUNC_20         0b00100000
 #define _TRACE_SET_FUNC_28         0b00110000
 #define _TRACE_SET_ELEM_AO         0b01000000
 #define _TRACE_SET_ELEM_PZ         0b01010000
 #define _TRACE_SET_ELEM2_ao        0b01100000
 #define _TRACE_SET_ELEM2_pz        0b01110000

#define _TRACE_TEST_LEN             0b00000111
 #define _TRACE_SET_LEN_0           0b00000000
 #define _TRACE_SET_LEN_8           0b00000001
 #define _TRACE_SET_LEN_16          0b00000010
 #define _TRACE_SET_LEN_32          0b00000011
 #define _TRACE_SET_LEN_64          0b00000100
 #define _TRACE_SET_LEN_PREFIX_res  0b00000101
 #define _TRACE_SET_LEN_STRING_res  0b00000110
 #define _TRACE_SET_LEN_BYTECOUNT   0b00000111

#define _TRACE_TEST_IS_ELEM         0b11100000
 #define _TRACE_SET_IS_ELEM         0b01000000

#define _TRACE_TEST_ELEM            0b11111111
 #define _TRACE_SET_END             0b01000101 // 'E'
 #define _TRACE_SET_RETURN          0b01010010 // 'R'
 #define _TRACE_SET_FUNC_ANON       0b01000001 // 'A'
 #define _TRACE_SET_TRY             0b01010011 // 'S'
 #define _TRACE_SET_UNTRY           0b01010101 // 'U'
 #define _TRACE_SET_PAUSE           0b01010000 // 'P'
/* FUNC_32 always comes with 32 bit function number */
 #define _TRACE_SET_FUNC_32         0b01000110 // 'F'
/* 'T' and 'N' could be used instead of
 * _TRACE_IE_BYTE_INIT for faster trace writing */
 #define _TRACE_SET_IF              0b01010100 // 'T'
 #define _TRACE_SET_ELSE            0b01001110 // 'N'
/* 'G' is reserved, use _TRACE_SET_FORK */
 #define _TRACE_SET_FORK_reserved   0b01000111 // 'G'
/* 'L' is reserved, use _TRACE_SET_CATCH */
 #define _TRACE_SET_CATCH_reserved  0b01001100 // 'L'
/* 'D' is reserved, use _TRACE_SET_DATA */
 #define _TRACE_SET_DATA_reserved   0b01000100 // 'D'
/* 'M' and 'B' are currently not supported */
 #define _TRACE_SET_FUNC_STRING_res 0b01001101 // 'M'
 #define _TRACE_SET_DATA_STRING_res 0b01000010 // 'B'

/* 'X' to '_' are reserved */
#define _TRACE_TEST_ELEM_reserved   0b11111000
 #define _TRACE_SET_ELEM_reserved   0b01011000

#define _TRACE_TEST_IS_ELEM2        0b11100000
 #define _TRACE_SET_IS_ELEM2        0b01100000

#define _TRACE_TEST_ELEM2           0b11111000
 #define _TRACE_SET_FORK            0b01100000
 #define _TRACE_SET_CATCH           0b01101000
 #define _TRACE_SET_DATA            0b01110000
 #define _TRACE_SET_ELEM2_reserved  0b01111000

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define _TRACE_PUT(c) ;{ \
    _trace_buf[_trace_buf_pos] = (c); \
    _trace_buf_pos += 1; \
    if (_trace_buf_pos == TRACE_BUF_SIZE) { \
        _trace_write(_trace_buf); \
        _trace_buf_pos = 0; \
    } \
}

#ifdef EFFICIENT_TEXT_TRACE
#define _TRACE_PUT_TEXT     _TRACE_PUT
#else
#define _TRACE_PUT_TEXT(c) ;{ \
    unsigned char buf[1] = { (c) }; \
    _trace_write_text(buf, 1); \
}
#endif

#ifdef BYTE_TRACE

#define _TRACE_IF()     _TRACE_PUT('T')
#define _TRACE_ELSE()   _TRACE_PUT('N')
#define _TRACE_IE_FINISH
#define _TRACE_IE(if_true) \
    if (if_true) { \
        _TRACE_IF(); \
    } else { \
        _TRACE_ELSE(); \
    }

#define _TRACE_CASE(num, bit_cnt) { \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        _TRACE_IE(num & (1 << i)); \
    } \
}
#else

// will get optimized as rotate instruction
#define rotate_8(x, n) \
    ((x << n) | (x >> (8 - n)))

#define _TRACE_IE_PREPARE_NEXT \
    if (_trace_ie_byte < 0b11000000) { \
        _TRACE_PUT(_trace_ie_byte); \
        _trace_ie_byte = _TRACE_IE_BYTE_INIT; \
    }

#define _TRACE_IE(if_true) { \
    _trace_ie_byte <<= 1; \
    _trace_ie_byte |= (bool)(if_true); \
    _TRACE_IE_PREPARE_NEXT \
}
#define _TRACE_IF() { \
    _trace_ie_byte = rotate_8(_trace_ie_byte, 1); \
    _TRACE_IE_PREPARE_NEXT \
}
#define _TRACE_ELSE() { \
    _trace_ie_byte <<= 1; \
    _TRACE_IE_PREPARE_NEXT \
}
#define _TRACE_IE_FINISH \
    if (_trace_ie_byte != _TRACE_IE_BYTE_INIT) { \
        _TRACE_PUT(_trace_ie_byte); \
        _trace_ie_byte = _TRACE_IE_BYTE_INIT; \
    }

#define _TRACE_CASE(num, bit_cnt) { \
    _TRACE_IE_FINISH \
    int bit_cnt_left = bit_cnt; \
    const int num_left = num; \
    while (bit_cnt_left >= 6) { \
        bit_cnt_left -= 6; \
        _TRACE_PUT(((num_left >> bit_cnt_left) & 0b00111111) | 0b10000000); \
    } \
    _trace_ie_byte = (num_left & ~(0b11111111 << bit_cnt_left) & 0b00111111) - (2 << bit_cnt_left); \
}

#endif // BYTE_TRACE

// functions numbers are now big endian for better conversion
#define _TRACE_FUNC(num) { \
    _TRACE_IE_FINISH \
    if ((num) == 0) { \
        _TRACE_PUT(_TRACE_SET_FUNC_ANON); \
    } else if ((num) == ((num) & 0xf)) { \
        _TRACE_PUT(_TRACE_SET_FUNC_4  | (((num) >> 0) & 0xff)); \
    } else if ((num) == ((num) & 0xfff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC_12 | (((num) >> 8) & 0xff)); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
    } else if ((num) == ((num) & 0xfffff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC_20 | (((num) >> 16) & 0xff)); \
        _TRACE_PUT(((num) >> 8) & 0xff); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
    } else if ((num) == ((num) & 0xfffffff)) { \
        _TRACE_PUT(_TRACE_SET_FUNC_28 | (((num) >> 24) & 0xff)); \
        _TRACE_PUT(((num) >> 16) & 0xff); \
        _TRACE_PUT(((num) >> 8) & 0xff); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
    } else { \
        _TRACE_PUT(_TRACE_SET_FUNC_32); \
        _TRACE_PUT(((num) >> 24) & 0xff); \
        _TRACE_PUT(((num) >> 16) & 0xff); \
        _TRACE_PUT(((num) >> 8) & 0xff); \
        _TRACE_PUT(((num) >> 0) & 0xff); \
    } \
}

#define _TRACE_NUM_0(type, num) { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(type | _TRACE_SET_LEN_0); \
}

#define _TRACE_NUM_8(type, num) { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(type | _TRACE_SET_LEN_8); \
    _TRACE_PUT(((num) >> 0) & 0xff); \
}

#define _TRACE_NUM_16(type, num) { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(type | _TRACE_SET_LEN_16); \
    _TRACE_PUT(((num) >> 0) & 0xff); \
    _TRACE_PUT(((num) >> 8) & 0xff); \
}

#define _TRACE_NUM_32(type, num) { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(type | _TRACE_SET_LEN_32); \
    _TRACE_PUT(((num) >> 0) & 0xff); \
    _TRACE_PUT(((num) >> 8) & 0xff); \
    _TRACE_PUT(((num) >> 16) & 0xff); \
    _TRACE_PUT(((num) >> 24) & 0xff); \
}

#define _TRACE_NUM_64(type, num) { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(type | _TRACE_SET_LEN_64); \
    _TRACE_PUT(((num) >> 0) & 0xff); \
    _TRACE_PUT(((num) >> 8) & 0xff); \
    _TRACE_PUT(((num) >> 16) & 0xff); \
    _TRACE_PUT(((num) >> 24) & 0xff); \
    _TRACE_PUT(((num) >> 32) & 0xff); \
    _TRACE_PUT(((num) >> 40) & 0xff); \
    _TRACE_PUT(((num) >> 48) & 0xff); \
    _TRACE_PUT(((num) >> 56) & 0xff); \
}

// data should be native endian (here little endian)
#define _TRACE_NUM(type, num) { \
    unsigned long long _trace_n = (num); \
    if (_trace_n == 0) { \
        _TRACE_NUM_0(type, _trace_n); \
    } else if (_trace_n == (_trace_n & 0xff)) { \
        _TRACE_NUM_8(type, _trace_n); \
    } else if (_trace_n == (_trace_n & 0xffff)) { \
        _TRACE_NUM_16(type, _trace_n); \
    } else if (_trace_n == (_trace_n & 0xffffffff)) { \
        _TRACE_NUM_32(type, _trace_n); \
    } else { \
        _TRACE_NUM_64(type, _trace_n); \
    } \
}

#define NIBBLE_TO_HEX_(n)   (((n) >= 0xa) ? (n) - 0xa + 'a' : (n) + '0')
#define NIBBLE_TO_HEX(n,i)  NIBBLE_TO_HEX_(((n) >> ((i)*4)) & 0xf)

// Shift twice, otherwise we might run into undefined behavior!
#define NIBBLE_COUNT(n,c)   (((n) >> (c)*3 >> (c)) != 0)

#ifdef EFFICIENT_TEXT_TRACE
#define _TRACE_NUM_TEXT(type, num) ;{ \
    int count; \
    _TRACE_PUT(type); \
    for (count = 0; NIBBLE_COUNT((num), count); count++) {}  \
    for (int i = count-1; i >= 0; i--) { \
        _TRACE_PUT(NIBBLE_TO_HEX((num), i)); \
    } \
}
#else
#define _TRACE_NUM_TEXT(type, num) ;{ \
    unsigned char buf[18]; \
    int count; \
    buf[0] = (type); \
    for (count = 0; NIBBLE_COUNT((num), count); count++) {}  \
    for (int i = 0; i < count; i++) { \
        buf[count-i] = NIBBLE_TO_HEX((num), i); \
    } \
    _trace_write_text(buf, 1+count); \
}
#endif

#define _TRACE_CASE_TEXT(num, bit_cnt) ; \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        if (num & (1 << i)) { \
            _TRACE_PUT_TEXT('T'); \
        } else { \
            _TRACE_PUT_TEXT('N'); \
        } \
    }

#define _TRACE_RETURN() { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(_TRACE_SET_RETURN); \
}

#define _TRACE_END() { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(_TRACE_SET_END); \
}

#define _TRACE_TRY() { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(_TRACE_SET_TRY); \
}

#define _TRACE_CATCH(cur_idx) \
    _TRACE_NUM_16(_TRACE_SET_CATCH, _trace_setjmp_idx - (cur_idx))

#define _TRACE_SETJMP(setjmp_stmt) ({ \
    _trace_setjmp_idx ++; \
    int cur_setjmp_idx = _trace_setjmp_idx; \
    _TRACE_TRY(); \
    int setjmp_res = setjmp_stmt; \
    if (setjmp_res != 0) { \
        _TRACE_CATCH(cur_setjmp_idx); \
    } \
    setjmp_res; \
})

// same as the macro version
// but returns num
// can be used inside switch conditions
static inline __attribute__((always_inline)) long long int _trace_num(char type, long long int num) {
    _TRACE_NUM(type, num);
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

extern volatile char _retrace_letter;
extern volatile long long int _retrace_num;
extern void _retrace_compare_elem(void);

extern volatile int _retrace_fork_count;

#define _RETRACE_ELEM(type, num) ;{ \
    _retrace_letter = (type); \
    _retrace_num = (num); \
    _retrace_compare_elem(); \
}

#define _RETRACE_FUNC(num) \
    _RETRACE_ELEM('F', num)

#define _RETRACE_RETURN() \
    _RETRACE_ELEM('R', 0)

#define _RETRACE_IF() \
    _RETRACE_ELEM('T', 0)

#define _RETRACE_ELSE() \
    _RETRACE_ELEM('N', 0)

#define _RETRACE_END() \
    _RETRACE_ELEM('E', 0)

#define _RETRACE_TRY() \
    _RETRACE_ELEM('S', 0)

#define _RETRACE_CATCH(idx) \
    _RETRACE_ELEM('L', _trace_setjmp_idx - (idx))

#define _RETRACE_SETJMP(setjmp_stmt) ({ \
    _trace_setjmp_idx ++; \
    int cur_setjmp_idx = _trace_setjmp_idx; \
    _RETRACE_TRY(); \
    int setjmp_res = setjmp_stmt; \
    if (setjmp_res != 0) { \
        _RETRACE_CATCH(cur_setjmp_idx); \
    } \
    setjmp_res; \
})

static inline __attribute__((always_inline)) long long int _retrace_elem(char type, long long int num) {
    _RETRACE_ELEM(type, num);
    return num;
}

static inline __attribute__((always_inline)) bool _retrace_condition(bool cond) {
    if (cond) {
        _retrace_letter = 'T';
    } else {
        _retrace_letter = 'N';
    }
    _retrace_num = 0;
    _retrace_compare_elem();
    return cond;
}

static inline __attribute__((always_inline)) int _retrace_after_fork(int fork_val) {
    if (fork_val != 0) {
        _retrace_letter = 'T';
    } else {
        _retrace_letter = 'N';
    }
    _retrace_num = 0;
    _retrace_compare_elem();
    return fork_val;
}

#define _RETRACE_CASE(num, bit_cnt) { \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        _retrace_condition(num & (1 << i)); \
    } \
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
        _IS_RETRACE(_RETRACE_IF(), _TRACE_IF());
    } else {
        _IS_RETRACE(_RETRACE_ELSE(), _TRACE_ELSE());
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
    _IS_RETRACE(_RETRACE_ELEM('D', num),
                _TRACE_NUM(_TRACE_SET_DATA, num)
    )
    return num;
}

#define _RETRO(normal, retro) \
    _RETRO_SKIP(normal) \
    _RETRO_ONLY(retro)

/*
 * Macros used in the instrumentation.
 * 2 versions: _TRACE_MODE and _RETRACE_MODE
 */

#if defined _TRACE_MODE && defined _RETRACE_MODE
/* combined trace/retrace mode, experimental */

#define _IF                 _IS_RETRACE(_RETRACE_IF(), _TRACE_IF())
#define _ELSE               _IS_RETRACE(_RETRACE_ELSE(), _TRACE_ELSE())
#define _CONDITION(cond)    _is_retrace_condition(cond)
#define _FUNC(num)          _IS_RETRACE(_RETRACE_FUNC(num), _TRACE_FUNC(num))
#define _FUNC_RETURN        _IS_RETRACE(_RETRACE_RETURN(), _TRACE_RETURN())
// non-macro version for switch
#define _SWITCH(num)        _is_retrace_switch(num)
// bit-trace version for switch
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _IS_RETRACE(_RETRACE_CASE(num, cnt), \
                                            _TRACE_CASE(num, cnt)) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      _IS_RETRACE(_RETRACE_IF(), _TRACE_IF())
#define _LOOP_END(id)       _IS_RETRACE(_RETRACE_ELSE(), _TRACE_ELSE())

#define _TRY                _IS_RETRACE(_RETRACE_TRY(), _TRACE_TRY())
#define _CATCH(idx)         _IS_RETRACE(_RETRACE_CATCH(idx), _TRACE_CATCH(idx))
#define _SETJMP(stmt)       _IS_RETRACE(_RETRACE_SETJMP(stmt), _TRACE_SETJMP(stmt))

#define _TRACE_OPEN(fname)  _IS_RETRACE( ,_trace_open((fname)))
#define _TRACE_CLOSE        _IS_RETRACE(_RETRACE_END() ,_trace_close())

#define _RETRO_ONLY(code)   _IS_RETRACE(code, )
#define _RETRO_SKIP(code)   _IS_RETRACE(, code)


#elif defined _TRACE_MODE
/* trace mode */

#define _IF                 ;_TRACE_IF();
#define _ELSE               ;_TRACE_ELSE();
#define _CONDITION(cond)    _trace_condition(cond)
#define _FUNC(num)          ;_TRACE_FUNC(num);
#define _FUNC_RETURN        ;_TRACE_RETURN();
// non-macro version for switch
#define _SWITCH(num)        _trace_num(_TRACE_SET_DATA, num)
// bit-trace version for switch
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _TRACE_CASE(num, cnt) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_TRACE_IF();
#define _LOOP_END(id)       ;_TRACE_ELSE();

#define _TRACE_OPEN(fname)  ;_trace_open((fname));
#define _TRACE_CLOSE        ;_trace_close();

#define _FORK(fork_stmt)    (_trace_before_fork(), \
                             _trace_after_fork(fork_stmt))
#define _TRY                ;_TRACE_TRY();
#define _CATCH(idx)         ;_TRACE_CATCH(idx);
#define _SETJMP(stmt)       _TRACE_SETJMP(stmt)

#define _RETRO_ONLY(code)   /* nothing here */
#define _RETRO_SKIP(code)   code


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
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _TRACE_CASE_TEXT(num, cnt); \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_TRACE_PUT_TEXT('T');
#define _LOOP_END(id)       ;_TRACE_PUT_TEXT('N');

#define _TRACE_OPEN(fname)  ;_trace_open(fname ".txt");
#define _TRACE_CLOSE        ;_trace_close();

#define _RETRO_ONLY(code)   /* nothing here */
#define _RETRO_SKIP(code)   code


#elif defined _RETRACE_MODE
/* retrace mode */

#define _IF                 ;_RETRACE_IF();
#define _ELSE               ;_RETRACE_ELSE();
#define _CONDITION(cond)    _retrace_condition(cond)
#define _FUNC(num)          ;_RETRACE_FUNC(num);
#define _FUNC_RETURN        ;_RETRACE_RETURN();
// non-macro version for switch
#define _SWITCH(num)        _retrace_elem('D', num)
// bit-trace version for switch
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _RETRACE_CASE(num, cnt) \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_RETRACE_IF();
#define _LOOP_END(id)       ;_RETRACE_ELSE();

#define _TRY                ;_RETRACE_TRY();
#define _CATCH(idx)         ;_RETRACE_CATCH(idx);
#define _SETJMP(stmt)       _RETRACE_SETJMP(stmt)

#define _TRACE_OPEN(fname)  /* nothing here */
#define _TRACE_CLOSE        ;_RETRACE_END();

#define _FORK(fork_stmt)    (_retrace_elem('G', _retrace_fork_count), \
                             _retrace_after_fork(fork_stmt))

#define _RETRO_ONLY(code)   code
#define _RETRO_SKIP(code)   /* nothing here */

#elif _CBMC_MODE

#include "retrace.h"

#define _RETRACE_CBMC(l, n) { \
    __CPROVER_assume(retrace_i < retrace_arr_len); \
    __CPROVER_assume(retrace_arr[retrace_i].letter == l); \
    __CPROVER_assume(retrace_arr[retrace_i].num == n); \
    retrace_i += 1; \
}

#define _RETRACE_CASE_CBMC(num, bit_cnt) ; \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        if (num & (1 << i)) { \
            _RETRACE_CBMC('T', 0); \
        } else { \
            _RETRACE_CBMC('N', 0); \
        } \
    }

#define _RETRACE_END_CBMC() { \
    _RETRACE_CBMC('E', 0); \
    __CPROVER_assume(retrace_i == retrace_arr_len); \
    /* now check all past assertions */ \
    for (int i = 0; i < _retrace_assert_idx; i++) { \
        /* does not work: \
        __CPROVER_assert(_retrace_asserts[i], \
                         _retrace_assert_names[i]); \
         * alternative: */ \
        assert(_retrace_asserts[i]); \
    } \
}

#define _RETRACE_SETJMP_CBMC(setjmp_stmt) ({ \
    _RETRACE_CBMC('S', 0); \
    _trace_setjmp_idx ++; \
    int cur_setjmp_idx = _trace_setjmp_idx; \
    int setjmp_res = setjmp_stmt; \
    if (setjmp_res != 0) { \
        _RETRACE_CBMC('L', _trace_setjmp_idx - cur_setjmp_idx); \
    } \
    setjmp_res; \
})

#define _IF                 ;_RETRACE_CBMC('T', 0);
#define _ELSE               ;_RETRACE_CBMC('N', 0);
#define _CONDITION(cond)    cond
#define _FUNC(num)          ;_RETRACE_CBMC('F', num);
#define _FUNC_RETURN        ;_RETRACE_CBMC('R', 0);
#define _SWITCH(num)        ;_RETRACE_CBMC('D', num);
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _RETRACE_CASE_CBMC(num, cnt); \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_RETRACE_CBMC('T', 0);
#define _LOOP_END(id)       ;_RETRACE_CBMC('N', 0);

#define _SETJMP(stmt)       _RETRACE_SETJMP_CBMC(stmt)

#define _TRACE_OPEN(fname)  ;retrace_i = 0;
#define _TRACE_CLOSE        ;_RETRACE_END_CBMC();

#define _FORK(fork_stmt)    fork_stmt

#define _RETRO_ONLY(code)   code
#define _RETRO_SKIP(code)   /* nothing here */

#else // neither _TRACE_MODE nor _RETRACE_MODE

#define _IF                 /* nothing here */
#define _ELSE               /* nothing here */
#define _CONDITION(cond)    cond
#define _FUNC(num)          /* nothing here */
#define _FUNC_RETURN        /* nothing here */
#define _SWITCH(num)        num
#define _SWITCH_START(id,cnt) /* nothing here */
#define _CASE(num, id, cnt) /* nothing here */
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      /* nothing here */
#define _LOOP_END(id)       /* nothing here */

#define _TRACE_OPEN(fname)  /* nothing here */
#define _TRACE_CLOSE        /* nothing here */

#define _FORK(fork_stmt)    fork_stmt
#define _TRY                /* nothing here */
#define _CATCH(idx)         /* nothing here */
#define _SETJMP(setjmp_stmt) setjmp_stmt

#define _RETRO_ONLY(code)   /* nothing here */
#define _RETRO_SKIP(code)   code

#endif // _TRACE_MODE or _RETRACE_MODE

#ifdef BOOL_ALREADY_DEFINED
#undef bool
#endif

#ifdef __cplusplus
} // end extern "C"
#endif
