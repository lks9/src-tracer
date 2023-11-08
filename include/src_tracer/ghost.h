// src_tracer_ghost.h

// This file does not have restrictions like src_trace.h
// so we can savely use include here.
#include <stdbool.h>

// editable constant definitions
#ifndef ASSERT_BUF_SIZE
#define ASSERT_BUF_SIZE 4096
#endif
#ifndef GHOST_DUMP_BUF_SIZE
#define GHOST_DUMP_BUF_SIZE 4096
#endif
#ifndef RETRACE_SYMBOLIC_SIZE
#define RETRACE_SYMBOLIC_SIZE 4096
#endif

// RETRO_GHOST( code; )
// You can annotate your software with ghost code that will only be
// executed in retrace mode.
// Example:
//
// RETRO_GHOST(
//     int ghostvar = 0;
// )
//
// RETRO_GHOST(
//     if (ghostvar > 0) {
//         foo();
//     }
// )
//
// etc.

#define RETRO_GHOST(code) \
    _RETRO_ONLY_NONREC(code, __COUNTER__)

// RETRO_ONLY( code; )
// Same as retro ghost, but also includeded in nested ghost code
//
// Example:
// RETRO_GHOST(RETRO_GHOST(dosomething)) /* dosomething is never executed */
// RETRO_GHOST(RETRO_ONLY( dosomething)) /* dosomething is executed in retrace mode */
#define RETRO_ONLY(code) \
    _RETRO_ONLY(code)

// RETRO_SKIP( code; )
// Counterpart to RETRO_ONLY()
#define RETRO_SKIP(code) \
    _RETRO_SKIP(code)

#define RETRO(normal_code, retro_code) \
    _RETRO(normal_code, retro_code)


// RETRO_SYMBOLIC( type, default_value )
// Get a fresh symbolic value in retrace mode. Outside retrace mode, the default value is taken.
//
// Example:
//      int x = 42;
// Modified as retro symbolic:
//      int x = RETRO_SYMBOLIC(int, 42);
#define RETRO_SYMBOLIC(type, default_value) \
    RETRO(default_value, \
          ((type)_retrace_symbolic[_retrace_symbolic_idx++])  \
    )

// check assertions in retrace mode

// RETRO_ASSERT(condition)

#define RETRO_ASSERT(condition) { \
    RETRO_GHOST( \
        _retrace_assert_names[_retrace_assert_idx] = LOCATION; \
        _retrace_asserts[_retrace_assert_idx] = (condition); \
        _retrace_assert_passed(); \
        _retrace_assert_idx += 1; \
    ) \
}

// RETRO_ASSUME(condition)

#define RETRO_ASSUME(condition) { \
    RETRO_GHOST( \
        _retrace_assume_name = LOCATION; \
        _retrace_assume = (condition); \
        _retrace_assume_passed(); \
    ) \
}

// RETRO_PROPOSE("label", condition)
// Could be either assertion, assumption or ignored, it's completely up to the retracer.
// If ignored, the condition is not evaluated at all. This speeds up retracing.

#define RETRO_PROPOSE(label, condition) { \
    RETRO_GHOST( \
        _retrace_assert_names[_retrace_assert_idx] = (label); \
        _retrace_prop_start(); \
        _retrace_asserts[_retrace_assert_idx] \
            = _retrace_prop_is_assert ? (condition) : 0; \
        _retrace_assume \
            = _retrace_prop_is_assume ? (condition) : 0; \
        _retrace_prop_passed(); \
        _retrace_assert_idx \
            += _retrace_prop_is_assert ? 1 :0; \
    ) \
}

// GHOST_DUMP("label", pointer)
// Dump a pointer to a list, which can be inspected from the retracer.

#define GHOST_DUMP(label, pointer) { \
    RETRO_GHOST( \
        _retrace_dump_names[_retrace_dump_idx] = (label); \
        _retrace_dumps[_retrace_dump_idx] = pointer; \
        _retrace_dump_passed(); \
        _retrace_dump_idx += 1; \
    ) \
}

// helper macros

#define _RETRO_ONLY_NONREC(code, id) \
    _RETRO_ONLY_NONREC_(code, id)

// No { } for ghost code (local variable scope)!
// But we don't want to evaluate ghost code recursively.
// Therefore, we use goto :'(
#define _RETRO_ONLY_NONREC_(code, id) \
    _RETRO_ONLY( \
        bool _retrace_temp_##id = _retrace_in_ghost; \
        _retrace_in_ghost = true; \
        if(_retrace_temp_##id) { \
            goto end_ghost_##id; \
        } \
        _retrace_ghost_start(); \
        code; \
        _retrace_ghost_end(); \
        _retrace_in_ghost = false; \
    end_ghost_##id: ; \
    )

// extern variables and functions
extern void _retrace_ghost_start(void);
extern void _retrace_ghost_end(void);
extern volatile bool _retrace_in_ghost;

extern char *volatile _retrace_assert_names[ASSERT_BUF_SIZE];
extern volatile bool  _retrace_asserts[ASSERT_BUF_SIZE];
extern volatile int   _retrace_assert_idx;
extern void  _retrace_assert_passed(void);

extern char *volatile _retrace_assume_name;
extern volatile bool  _retrace_assume;
extern void  _retrace_assume_passed(void);

extern void _retrace_prop_start(void);
extern volatile bool _retrace_prop_is_assert;
extern volatile bool _retrace_prop_is_assume;
extern void _retrace_prop_passed(void);

extern char *volatile _retrace_dump_names[GHOST_DUMP_BUF_SIZE];
extern void *volatile _retrace_dumps[GHOST_DUMP_BUF_SIZE];
extern volatile int   _retrace_dump_idx;
extern void  _retrace_dump_passed(void);

extern long long *volatile _retrace_symbolic[RETRACE_SYMBOLIC_SIZE];
extern volatile int _retrace_symbolic_idx;

// helper macros
#define STR_(t)     #t
#define STR(t)      STR_(t)
#define LOCATION    (__FILE__ ":" STR(__LINE__))
