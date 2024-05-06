/*
   src_tracer/trace_mode.h
   functions and macros for the trace mode
*/
#ifndef SRC_TRACER_TRACE_MODE_H
#define SRC_TRACER_TRACE_MODE_H

#include "src_tracer/constants.h"
#include "src_tracer/mode_common.h"
#include "src_tracer/trace_buf.h"
#include "src_tracer/trace_elem.h"

#ifndef SRC_TRACER_STDINC_REPLACE_H
#include <stdbool.h>
#endif

extern void _trace_open(const char *fname);
extern void _trace_close(void);
extern void _trace_before_fork(void);
extern int _trace_after_fork(int pid);

#ifdef TRACE_USE_RINGBUFFER
#define _TRACE_PUT(c) ;{ \
    _trace_buf[_trace_buf_pos] = (c); \
    _trace_buf_pos += 1; \
}
#else
#define _TRACE_PUT(c) ;{ \
    _trace_buf[_trace_buf_pos] = (c); \
    _trace_buf_pos += 1; \
    if (_trace_buf_pos == TRACE_BUF_SIZE) { \
        _trace_write(_trace_buf); \
        _trace_buf_pos = 0; \
    } \
}
#endif

#ifdef BYTE_TRACE

#define _TRACE_IF()     _TRACE_PUT('I')
#define _TRACE_ELSE()   _TRACE_PUT('O')
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
        _trace_ie_byte = _TRACE_SET_IE_INIT; \
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
    if (_trace_ie_byte != _TRACE_SET_IE_INIT) { \
        _TRACE_PUT(_trace_ie_byte); \
        _trace_ie_byte = _TRACE_SET_IE_INIT; \
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
#define _TRACE_FUNC_CORE(num) { \
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

#ifdef _TRACE_POINTER_CALLS_ONLY

#define _TRACE_FUNC(num) \
    _TRACE_POINTER_CALL_INIT \
    _TRACE_IE_FINISH \
    if (_TRACE_CALL_CHECK) { \
        _TRACE_FUNC_CORE(num) \
        _TRACE_POINTER_CALL_RESET \
    } \

#define _TRACE_STATIC_FUNC(num) \
    _TRACE_POINTER_CALL_INIT \
    if (_TRACE_CALL_CHECK) { \
        _TRACE_IE_FINISH \
        _TRACE_FUNC_CORE(num) \
        _TRACE_POINTER_CALL_RESET \
    }

#else
#define _TRACE_FUNC(num) \
    _TRACE_IE_FINISH \
    _TRACE_FUNC_CORE(num)
#define _TRACE_STATIC_FUNC(num) \
    _TRACE_FUNC(num)
#endif

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

#define _TRACE_RETURN(type) \
    if (_TRACE_RETURN_CHECK) { \
        _TRACE_IE_FINISH \
        _TRACE_PUT(type); \
    }

#define _TRACE_END() { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(_TRACE_SET_END); \
}

#define _TRACE_TRY() { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(_TRACE_SET_TRY); \
}

#define _TRACE_CATCH(cur_idx) { \
    _TRACE_NUM_16(_TRACE_SET_CATCH, _trace_setjmp_idx - (cur_idx)); \
    /* _trace_setjmp_idx = cur_idx; */ \
}

#if 0
#define _TRACE_TRY_END() { \
    _TRACE_IE_FINISH \
    _TRACE_PUT(_TRACE_SET_UNTRY); \
    _trace_setjmp_idx --; \
}
#else
#define _TRACE_TRY_END() /* nothing here */
#endif

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

static inline __attribute__((always_inline)) bool _trace_condition(bool cond) {
    _TRACE_IE(cond);
    return cond;
}

#endif // SRC_TRACER_TRACE_MODE_H
