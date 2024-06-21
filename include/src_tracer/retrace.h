/*
   src_tracer/retrace.h
   functions and macros for cbmc retracing mode, assume(...)-approach
*/
#ifndef SRC_TRACER_RETRACE_H
#define SRC_TRACER_RETRACE_H

#include "src_tracer/constants.h"
#include "src_tracer/mode_common.h"

/*
 * trace array for symbolic replay using assume(retrace_arr[retrace_i++] == ...)
 * Used in _CBMC_MODE
 */
struct retrace_elem {
    char letter;
    int num;
};

#define RETRACE_ARR_LEN_MAX 4096
extern int retrace_i;

// to be defined for the respective trace
extern struct retrace_elem retrace_arr[RETRACE_ARR_LEN_MAX];
extern int retrace_arr_len;

#ifndef ASSERT_BUF_SIZE
#define ASSERT_BUF_SIZE 4096
#endif

// FIXME use assert array

#endif // SRC_TRACER_RETRACE_H
