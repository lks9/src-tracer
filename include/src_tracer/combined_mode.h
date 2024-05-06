/*
   src_tracer/combined_mode.h
   functions and macros for combined tracing and retracing
*/
#ifndef SRC_TRACER_COMBINED_MODE_H
#define SRC_TRACER_COMBINED_MODE_H

#include "src_tracer/constants.h"
#include "src_tracer/mode_common.h"
#include "src_tracer/trace_buf.h"
#include "src_tracer/trace_elem.h"

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

#endif // SRC_TRACER_COMBINED_MODE_H
