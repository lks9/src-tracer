/*
   src_tracer/mode_common.h
   functions and macros for all (re)tracing modes
*/
#ifndef SRC_TRACER_MODE_COMMON_H
#define SRC_TRACER_MODE_COMMON_H

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* try/catch/setjmp */
extern unsigned long long int _trace_setjmp_idx;

/* Pointer calls */
#ifdef _TRACE_POINTER_CALLS_ONLY

extern bool _trace_pointer_call;

#define _TRACE_POINTER_CALL_INIT \
    bool _trace_local_return __attribute__((unused)) = 0;

#define _TRACE_POINTER_CALL_SET \
    _trace_pointer_call = 1;

#define _TRACE_POINTER_CALL_RESET \
    _trace_pointer_call = 0; \
    _trace_local_return = 1;

#define _TRACE_CALL_CHECK _trace_pointer_call
#define _TRACE_RETURN_CHECK _trace_local_return

#define _TRACE_POINTER_CALL(call) ({ \
    _TRACE_POINTER_CALL_SET; \
    call; \
})
#define _TRACE_POINTER_CALL_AFTER(type, call) ({ \
    type _trace_call_tmp = call; \
    _TRACE_POINTER_CALL_SET; \
    _trace_call_tmp; \
})

#else
#define _TRACE_POINTER_CALL_INIT /* nothing here */
#define _TRACE_CALL_CHECK 1
#define _TRACE_POINTER_CALL_SET /* nothing here */
#define _TRACE_POINTER_CALL_RESET /* nothing here */
#define _TRACE_POINTER_CALL(call) call
#define _TRACE_POINTER_CALL_AFTER(type, call) call
#define _TRACE_RETURN_CHECK 1
#endif

/* return after */
#define _FUNC_RETURN_AFTER(ret, type, expr) { \
    type _trace_return_result = (expr); \
    _FUNC_RETURN \
    return _trace_return_result; \
}
#define _FUNC_RETURN_VOID_AFTER(ret, type, expr) { \
    (expr); \
    _FUNC_RETURN \
    return; \
}
#define _TRACE_CLOSE_AFTER(ret, type, expr) { \
    type _trace_return_result = (expr); \
    _TRACE_CLOSE \
    return _trace_return_result; \
}
#define _TRACE_CLOSE_VOID_AFTER(ret, type, expr) { \
    (expr); \
    _TRACE_CLOSE \
    return; \
}
#define _FUNC_RETURN_TRACE_CLOSE_AFTER(ret, type, expr) { \
    type _trace_return_result = (expr); \
    _FUNC_RETURN \
    _TRACE_CLOSE \
    return _trace_return_result; \
}
#define _FUNC_RETURN_TRACE_CLOSE_VOID_AFTER(ret, type, expr) { \
    (expr); \
    _FUNC_RETURN \
    _TRACE_CLOSE \
    return; \
}

#endif // SRC_TRACER_MODE_COMMON_H
