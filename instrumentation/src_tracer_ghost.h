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

// GHOST( code; )
// You can annotate your software with ghost code that will only be
// executed in retrace mode.
// Example:
//
// GHOST(
//     int ghostvar = 0;
// )
//
// GHOST(
//     if (ghostvar > 0) {
//         foo();
//     }
// )
//
// etc.

#define GHOST(code) \
    _GHOST_NONREC_(code, __COUNTER__)

#define _GHOST_NONREC_(code, id) \
    _GHOST_NONREC(code, id)

// No { } for ghost code (local variable scope)!
// But we don't want to evaluate ghost code recursively.
// Therefore, we use goto :'(
#define _GHOST_NONREC(code, id) \
    _GHOST( \
        bool _retrace_temp_##id = _retrace_in_ghost; \
        _retrace_in_ghost = true; \
        _retrace_ghost_start(); \
        if(_retrace_temp_##id) { \
            goto end_ghost_##id; \
        } \
        code; \
        _retrace_ghost_end(); \
        _retrace_in_ghost = false; \
    end_ghost_##id: ; \
    );

// check assertions in retrace mode

// ASSERT(condition)

#define ASSERT(condition) \
    GHOST( \
        _retrace_assert_names[_retrace_assert_idx] = LOCATION; \
        _retrace_asserts[_retrace_assert_idx] = (condition); \
        _retrace_assert_passed(); \
        _retrace_assert_idx += 1; \
    )

// ASSUME(condition)

#define ASSUME(condition) \
    GHOST( \
        _retrace_assume_name = LOCATION; \
        _retrace_assume = (condition); \
        _retrace_assume_passed(); \
    )

// PROPOSE("label", condition)
// Could be either assertion, assumption or ignored, it's completely up to the retracer.
// If ignored, the condition is not evaluated at all. This speeds up retracing.

#define PROPOSE(label, condition) \
    GHOST( \
        _retrace_assert_names[_retrace_assert_idx] = (label); \
        _retrace_prop_start(); \
        _retrace_asserts[_retrace_assert_idx] \
            = _retrace_prop_is_assert ? (condition) : 0; \
        _retrace_assume \
            = _retrace_prop_is_assume ? (condition) : 0; \
        _retrace_prop_passed(); \
        _retrace_assert_idx \
            += _retrace_prop_is_assert ? 1 :0; \
    )

// GHOST_DUMP("label", pointer)
// Dump a pointer to a list, which can be inspected from the retracer.

#define GHOST_DUMP(label, pointer) \
    GHOST( \
        _retrace_dump_names[_retrace_dump_idx] = (label); \
        _retrace_dumps[_retrace_dump_idx] = pointer; \
        _retrace_dump_passed(); \
        _retrace_dump_idx += 1; \
    )

// extern variables and functions
extern void _retrace_ghost_start(void);
extern void _retrace_ghost_end(void);
extern bool _retrace_in_ghost;

extern char *_retrace_assert_names[ASSERT_BUF_SIZE];
extern bool  _retrace_asserts[ASSERT_BUF_SIZE];
extern int   _retrace_assert_idx;
extern void  _retrace_assert_passed(void);

extern char *_retrace_assume_name;
extern bool  _retrace_assume;
extern void  _retrace_assume_passed(void);

extern void _retrace_prop_start(void);
extern bool _retrace_prop_is_assert;
extern bool _retrace_prop_is_assume;
extern void _retrace_prop_passed(void);

extern char *_retrace_dump_names[GHOST_DUMP_BUF_SIZE];
extern void *_retrace_dumps[GHOST_DUMP_BUF_SIZE];
extern int   _retrace_dump_idx;
extern void  _retrace_dump_passed(void);

// helper macros
#define STR_(t)     #t
#define STR(t)      STR_(t)
#define LOCATION    (__FILE__ ":" STR(__LINE__))
