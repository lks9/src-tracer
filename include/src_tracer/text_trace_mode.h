/*
   src_tracer/trace_mode.h
   functions and macros for the text trace mode
*/

#ifndef SRC_TRACER_TEXT_TRACE_MODE_H
#define SRC_TRACER_TEXT_TRACE_MODE_H

#include "src_tracer/constants.h"
#include "src_tracer/mode_common.h"
#include "src_tracer/trace_buf.h"
#include "src_tracer/trace_elem.h"

extern void _trace_open(const char *fname, const char *suffix);
extern void _trace_close(void);
extern void _trace_before_fork(void);
extern int _trace_after_fork(int pid);
extern void _trace_write_text(const void *buf, unsigned long count);

#define _TRACE_FNAME_SUFFIX ".trace.txt"

#define _TRACE_PUT_TEXT(c) ;{ \
    unsigned char buf[1] = { (c) }; \
    _trace_write_text(buf, 1); \
}

#define NIBBLE_TO_HEX_(n)   (((n) >= 0xa) ? (n) - 0xa + 'a' : (n) + '0')
#define NIBBLE_TO_HEX(n,i)  NIBBLE_TO_HEX_(((n) >> ((i)*4)) & 0xf)

// Shift twice, otherwise we might run into undefined behavior!
#define NIBBLE_COUNT(n,c)   (((n) >> (c)*3 >> (c)) != 0)

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

#define _TRACE_CASE_TEXT(num, bit_cnt) ; \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        if (num & (1 << i)) { \
            _TRACE_PUT_TEXT('I'); \
        } else { \
            _TRACE_PUT_TEXT('O'); \
        } \
    }

static inline __attribute__((always_inline)) long long int _trace_num_text(char type, long long int num) {
    _TRACE_NUM_TEXT(type, num);
    return num;
}

static inline __attribute__((always_inline)) my_bool _text_trace_condition(my_bool cond) {
    if (cond) {
        _TRACE_PUT_TEXT('I');
    } else {
        _TRACE_PUT_TEXT('O');
    }
    return cond;
}

#endif // SRC_TRACER_TEXT_TRACE_MODE_H
