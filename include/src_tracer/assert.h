// src_tracer/assert.h
//
// This file defines TRACER_ASSERT(condition).
// For every assertion failure:
//   * It writes out bugreport-<TIME>.trace when _TRACE_DO_BUGREPORTS is set
//   * Afterwards, it calls assert(3) and terminates (unless NDEBUG is set)

#include <assert.h>

#include <src_tracer/constants.h>
#include <src_tracer/trace_buf.h>

#ifdef _TRACE_DO_BUGREPORTS
  #define TRACER_ASSERT(condition) \
      if ( ! (condition)) { \
          _trace_bugreport(); \
          assert(0!=0); \
      }
#else
  #define TRACER_ASSERT(condition) \
      assert(condition)
#endif
