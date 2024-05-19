/*
   src_tracer/_after_instrument.h
   automatically included after running instrumenter.py
*/
// This file comes without any standard library include.
// Reason: It works on pre-processed files.
// A "#include <stdbool.h>" would result in double included files!
#include "src_tracer/_stdinc_replace.h"

// assumes char is 8 bit!
#include "src_tracer/constants.h"

#include "src_tracer/trace_elem.h"
#include "src_tracer/trace_buf.h"

// and here comes the rest...
#ifdef _TRACE_MODE
    #include "src_tracer/trace_mode.h"
#endif
#ifdef _TEXT_TRACE_MODE
    #include "src_tracer/text_trace_mode.h"
#endif

// for retracing
#ifdef _RETRACE_MODE
    #include "src_tracer/retrace_mode.h"
#endif
#ifdef _CMBC_MODE
    #include "src_tracer/cbmc_mode.h"
#endif

// for combined tracing and retracing
#if defined _TRACE_MODE && defined _RETRACE_MODE
    #include "src_tracer/combined_mode.h"
#endif


#define _RETRO(normal, retro) \
    _RETRO_SKIP(normal) \
    _RETRO_ONLY(retro)

/* Macros that translate to macros */
#if defined _TRACE_MODE || defined _RETRACE_MODE || defined _TEXT_TRACE_MODE || defined _CBMC_MODE
#define _SETJMP(setjmp_stmt) ({ \
    _TRY \
    _trace_setjmp_idx ++; \
    int cur_setjmp_idx = _trace_setjmp_idx; \
    int setjmp_res = setjmp_stmt; \
    if (setjmp_res != 0) { \
        _CATCH(cur_setjmp_idx) \
    } \
    setjmp_res; \
})

#define _FORK(fork_stmt) ({ \
    _BEFORE_FORK \
    _TRACING_PAUSE \
    int fork_res = fork_stmt; \
    if (fork_res != 0) { \
        /* in parent */ \
        _TRACING_RESUME \
        _IF \
    } else { \
        _IN_FORK_CHILD \
        _ELSE \
    } \
    fork_res; \
})
#else
#define _SETJMP(setjmp_stmt) setjmp_stmt
#define _FORK(fork_stmt) fork_stmt
#endif

/*
 * Macros used in the instrumentation.
 * versions: _TRACE_MODE and _RETRACE_MODE
 * and similar
 */

#if defined _TRACE_MODE && defined _RETRACE_MODE
/* combined trace/retrace mode, experimental */

#define _IF                 _IS_RETRACE(_RETRACE_IF(), _TRACE_IF())
#define _ELSE               _IS_RETRACE(_RETRACE_ELSE(), _TRACE_ELSE())
#define _CONDITION(cond)    _is_retrace_condition(cond)
#define _FUNC(num)          _IS_RETRACE(_RETRACE_FUNC(num), _TRACE_FUNC(num))
#define _STATIC_FUNC(num)   _IS_RETRACE(_RETRACE_FUNC(num), _TRACE_STATIC_FUNC(num))
#define _FUNC_RETURN        _IS_RETRACE(_RETRACE_RETURN('R'), _TRACE_RETURN(_TRACE_SET_RETURN))
#define _FUNC_RETURN_TAIL   _IS_RETRACE(_RETRACE_RETURN('S'), _TRACE_RETURN(_TRACE_SET_RETURN_TAIL))
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
#define _TRY_END            _IS_RETRACE(_RETRACE_TRY_END(), _TRACE_TRY_END())

#define _TRACE_OPEN(fname)  _IS_RETRACE( ,_trace_open((fname), _TRACE_FNAME_SUFFIX)); \
                            _IS_RETRACE( ,_trace_buf_pos = 0); \
                            _IS_RETRACE( ,_TRACE_IE_INIT); \
                            _TRACE_POINTER_CALL_SET;
#define _TRACE_CLOSE        _IS_RETRACE(_RETRACE_END(), _TRACE_END()); \
                            _IS_RETRACE( ,_trace_close())

#define _BEFORE_FORK        ;_trace_fork_count += 1; \
                            _IS_RETRACE(_RETRACE_ELEM('F', _trace_fork_count), \
                                        _TRACE_NUM(_TRACE_SET_FORK, _trace_fork_count));
#define _TRACING_PAUSE      _IS_RETRACE( ,_TRACE_IE_FINISH); \
                            _IS_RETRACE( ,_trace_pause());
#define _TRACING_RESUME     _IS_RETRACE( ,_trace_resume()); \
                            _IS_RETRACE( ,_TRACE_IE_INIT);
#define _IN_FORK_CHILD      _IS_RETRACE( ,_trace_in_fork_child()); \
                            _IS_RETRACE( ,_trace_buf_pos = 0); \
                            _IS_RETRACE( ,_TRACE_IE_INIT);

#define _POINTER_CALL(call) _TRACE_POINTER_CALL(call)
#define _POINTER_CALL_AFTER(type, call) \
                            _TRACE_POINTER_CALL_AFTER(type, call)

#define _RETRO_ONLY(code)   _IS_RETRACE(code, )
#define _RETRO_SKIP(code)   _IS_RETRACE(, code)


#elif defined _TRACE_MODE
/* trace mode */

#define _IF                 ;_TRACE_IF();
#define _ELSE               ;_TRACE_ELSE();
#define _CONDITION(cond)    _trace_condition(cond)
#define _FUNC(num)          ;_TRACE_FUNC(num);
#define _STATIC_FUNC(num)   ;_TRACE_STATIC_FUNC(num);
#define _FUNC_RETURN        ;_TRACE_RETURN(_TRACE_SET_RETURN);
#define _FUNC_RETURN_TAIL   ;_TRACE_RETURN(_TRACE_SET_RETURN_TAIL);
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

#define _TRACE_OPEN(fname)  ;_trace_open((fname), _TRACE_FNAME_SUFFIX); \
                             _trace_buf_pos = 0; \
                             _TRACE_IE_INIT; \
                             _TRACE_POINTER_CALL_SET;
#define _TRACE_CLOSE        ;_TRACE_END(); \
                             _trace_close();

#define _BEFORE_FORK        ;_trace_fork_count += 1; \
                             _TRACE_NUM(_TRACE_SET_FORK, _trace_fork_count);
#define _TRACING_PAUSE      ;_TRACE_IE_FINISH; \
                             _trace_pause();
#define _TRACING_RESUME     ;_trace_resume(); \
                             _TRACE_IE_INIT;
#define _IN_FORK_CHILD      ;_trace_in_fork_child(); \
                             _trace_buf_pos = 0; \
                             _TRACE_IE_INIT;

#define _TRY                ;_TRACE_TRY();
#define _CATCH(idx)         ;_TRACE_CATCH(idx);
#define _TRY_END            ;_TRACE_TRY_END();

#define _POINTER_CALL(call) _TRACE_POINTER_CALL(call)
#define _POINTER_CALL_AFTER(type, call) \
                            _TRACE_POINTER_CALL_AFTER(type, call)

#define _RETRO_ONLY(code)   /* nothing here */
#define _RETRO_SKIP(code)   code


#elif defined _TEXT_TRACE_MODE
/* text trace mode, experimental */

#define _IF                 ;_TRACE_PUT_TEXT('I');
#define _ELSE               ;_TRACE_PUT_TEXT('O');
#define _CONDITION(cond)    _text_trace_condition(cond)
#define _FUNC(num)          ;_TRACE_NUM_TEXT('C', ((unsigned int)(num)));
#define _STATIC_FUNC(num)   _FUNC(num)
#define _FUNC_RETURN        ;_TRACE_PUT_TEXT('R');
#define _FUNC_RETURN_TAIL   ;_TRACE_PUT_TEXT('S');
// non-macro version for switch
#define _SWITCH(num)        _trace_num_text('D', ((unsigned int)(num)))
// experimental version for switch
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _TRACE_CASE_TEXT(num, cnt); \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_TRACE_PUT_TEXT('I');
#define _LOOP_END(id)       ;_TRACE_PUT_TEXT('O');

#define _TRACE_OPEN(fname)  ;_trace_open(fname, _TRACE_FNAME_SUFFIX);
#define _TRACE_CLOSE        ;_TRACE_PUT_TEXT('E'); \
                             _trace_close();
#define _BEFORE_FORK        ;_trace_fork_count += 1; \
                             _TRACE_NUM_TEXT('F', _trace_fork_count);
#define _TRACING_PAUSE      ;_trace_pause();
#define _TRACING_RESUME     ;_trace_resume();
#define _IN_FORK_CHILD      ;_trace_in_fork_child();

#define _RETRO_ONLY(code)   /* nothing here */
#define _RETRO_SKIP(code)   code


#elif defined _RETRACE_MODE
/* retrace mode */

#define _IF                 ;_RETRACE_IF();
#define _ELSE               ;_RETRACE_ELSE();
#define _CONDITION(cond)    _retrace_condition(cond)
#define _FUNC(num)          ;_RETRACE_FUNC(num);
#define _STATIC_FUNC(num)   _FUNC(num)
#define _FUNC_RETURN        ;_RETRACE_RETURN('R');
#define _FUNC_RETURN_TAIL   ;_RETRACE_RETURN('S');
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
#define _TRY_END            ;_RETRACE_TRY_END();

#define _TRACE_OPEN(fname)  ;_TRACE_POINTER_CALL_SET;
#define _TRACE_CLOSE        ;_RETRACE_END();

#define _BEFORE_FORK        ;_trace_fork_count += 1; \
                             _RETRACE_ELEM('F', _trace_fork_count);
// TODO
#define _TRACING_PAUSE      /* nothing here */
#define _TRACING_RESUME     /* nothing here */
#define _IN_FORK_CHILD      _TRACING_RESUME

#define _POINTER_CALL(call) _TRACE_POINTER_CALL(call)
#define _POINTER_CALL_AFTER(type, call) \
                            _TRACE_POINTER_CALL_AFTER(type, call)

#define _RETRO_ONLY(code)   code
#define _RETRO_SKIP(code)   /* nothing here */

#elif _CBMC_MODE

#define _IF                 ;_RETRACE_CBMC('I', 0);
#define _ELSE               ;_RETRACE_CBMC('O', 0);
#define _CONDITION(cond)    cond
#define _FUNC(num)          _TRACE_POINTER_CALL_INIT; _RETRACE_FUNC_CBMC(num);
#define _STATIC_FUNC(num)   _FUNC(num)
#define _FUNC_RETURN        ;if(_TRACE_RETURN_CHECK) { _RETRACE_CBMC('R', 0); };
#define _FUNC_RETURN_TAIL   ;if(_TRACE_RETURN_CHECK) { _RETRACE_CBMC('S', 0); };
#define _SWITCH(num)        ;_RETRACE_CBMC('D', num);
#define _SWITCH_START(id,cnt) ;bool _cflow_switch_##id = 1;
#define _CASE(num, id, cnt) ;if (_cflow_switch_##id) { \
                                _RETRACE_CASE_CBMC(num, cnt); \
                                _cflow_switch_##id = 0; \
                            };
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      ;_RETRACE_CBMC('I', 0);
#define _LOOP_END(id)       ;_RETRACE_CBMC('O', 0);

#define _TRACE_OPEN(fname)  ;_TRACE_POINTER_CALL_SET; retrace_i = 0;
#define _TRACE_CLOSE        ;_RETRACE_END_CBMC();

// TODO
#define _TRACING_PAUSE      /* nothing here */
#define _TRACING_RESUME     /* nothing here */

#define _BEFORE_FORK        ;_trace_fork_count += 1; \
                             _RETRACE_CBMC('F', _trace_fork_count);
#define _IN_FORK_CHILD      _TRACING_RESUME

#define _TRY                ;_RETRACE_CBMC('T', 0);
#define _CATCH(idx)         ;_RETRACE_CBMC('J', _trace_setjmp_idx - idx);

#define _POINTER_CALL(call) _TRACE_POINTER_CALL(call)
#define _POINTER_CALL_AFTER(type, call) \
                            _TRACE_POINTER_CALL_AFTER(type, call)

#define _RETRO_ONLY(code)   code
#define _RETRO_SKIP(code)   /* nothing here */

#else // neither _TRACE_MODE nor _RETRACE_MODE

#define _IF                 /* nothing here */
#define _ELSE               /* nothing here */
#define _CONDITION(cond)    cond
#define _FUNC(num)          /* nothing here */
#define _STATIC_FUNC(num)   /* nothing here */
#define _FUNC_RETURN        /* nothing here */
#define _FUNC_RETURN_TAIL   /* nothing here */
#define _SWITCH(num)        num
#define _SWITCH_START(id,cnt) /* nothing here */
#define _CASE(num, id, cnt) /* nothing here */
#define _LOOP_START(id)     /* nothing here */
#define _LOOP_BODY(id)      /* nothing here */
#define _LOOP_END(id)       /* nothing here */

#define _TRACE_OPEN(fname)  /* nothing here */
#define _TRACE_CLOSE        /* nothing here */

#define _TRACING_PAUSE      /* nothing here */
#define _TRACING_RESUME     /* nothing here */
#define _TRY                /* nothing here */
#define _CATCH(idx)         /* nothing here */
#define _TRY_END            /* nothing here */

#define _POINTER_CALL(call) call
#define _POINTER_CALL_AFTER(type, call) call

#define _RETRO_ONLY(code)   /* nothing here */
#define _RETRO_SKIP(code)   code

#endif // _TRACE_MODE or _RETRACE_MODE


// quickfix...
#ifdef BOOL_ALREADY_DEFINED
    #undef bool
#endif

#ifdef __cplusplus
} // end extern "C"
#endif
