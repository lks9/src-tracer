/*
   src_tracer/cbmc_common.h
   functions and macros for cbmc retracing mode, assume(...)-approach
*/
#ifndef SRC_TRACER_CBMC_MODE_H
#define SRC_TRACER_CBMC_MODE_H

#include "src_tracer/constants.h"
#include "src_tracer/mode_common.h"

#include "src_tracer/retrace.h"

#define _RETRACE_CBMC(l, n) { \
    __CPROVER_assume(retrace_i < retrace_arr_len); \
    __CPROVER_assume(retrace_arr[retrace_i].letter == l); \
    __CPROVER_assume(retrace_arr[retrace_i].num == n); \
    retrace_i += 1; \
}

#define _RETRACE_CASE_CBMC(num, bit_cnt) ; \
    for (int i = bit_cnt-1; i >= 0; i--) { \
        if (num & (1 << i)) { \
            _RETRACE_CBMC('I', 0); \
        } else { \
            _RETRACE_CBMC('O', 0); \
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

#define _RETRACE_FUNC_CBMC(num) \
    if (_TRACE_CALL_CHECK) { \
        _RETRACE_CBMC('C', num); \
        _TRACE_POINTER_CALL_RESET; \
    }

#endif // SRC_TRACER_CBMC_MODE_H
