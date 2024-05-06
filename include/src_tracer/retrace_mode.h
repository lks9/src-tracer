/*
   src_tracer/mode_common.h
   functions and macros for all (re)tracing modes
*/
#ifndef SRC_TRACER_RETRACE_MODE_H
#define SRC_TRACER_RETRACE_MODE_H

#include "src_tracer/constants.h"
#include "src_tracer/mode_common.h"

#ifndef SRC_TRACER_STDINC_REPLACE_H
#include <stdbool.h>
#endif

extern volatile char _retrace_letter;
extern volatile long long int _retrace_num;
extern void _retrace_breakpoint(void);

extern volatile int _retrace_fork_count;

#define _RETRACE_ELEM(type, num) ;{ \
    _retrace_letter = (type); \
    _retrace_num = (num); \
    _retrace_breakpoint(); \
}

#define _RETRACE_FUNC(num) \
    _TRACE_POINTER_CALL_INIT \
    if (_TRACE_CALL_CHECK) { \
        _RETRACE_ELEM('C', num); \
        _TRACE_POINTER_CALL_RESET; \
    }

#define _RETRACE_RETURN(type) \
    if (_TRACE_RETURN_CHECK) { \
        _RETRACE_ELEM(type, 0); \
    }

#define _RETRACE_IF() \
    _RETRACE_ELEM('I', 0)

#define _RETRACE_ELSE() \
    _RETRACE_ELEM('O', 0)

#define _RETRACE_END() \
    _RETRACE_ELEM('E', 0)

#define _RETRACE_TRY() \
    _RETRACE_ELEM('T', 0)

#define _RETRACE_CATCH(cur_idx) { \
    _RETRACE_ELEM('J', _trace_setjmp_idx - (cur_idx)); \
    /* _trace_setjmp_idx = cur_idx; */ \
}

#if 0
#define _RETRACE_TRY_END() { \
    _RETRACE_ELEM('U', 0) \
    _trace_setjmp_idx --; \
}
#else
#define _RETRACE_TRY_END() /* nothing here */
#endif

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
        _retrace_letter = 'I';
    } else {
        _retrace_letter = 'O';
    }
    _retrace_num = 0;
    _retrace_breakpoint();
    return cond;
}

static inline __attribute__((always_inline)) int _retrace_after_fork(int fork_val) {
    if (fork_val != 0) {
        _retrace_letter = 'I';
    } else {
        _retrace_letter = 'O';
    }
    _retrace_num = 0;
    _retrace_breakpoint();
    return fork_val;
}

#define _RETRACE_CASE(num, bit_cnt) { \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        _retrace_condition(num & (1 << i)); \
    } \
}

#endif // SRC_TRACER_RETRACE_MODE_H
