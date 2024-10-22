#!/usr/bin/env bash

# set up all the variables for instrumentation & compilation with gcc

# only execute if not defined yet
if [ -z "${SRC_TRACER_INCL}" ];
then
    source env.sh
fi

export CC="gcc"

export CFLAGS="${CFLAGS} -L${SRC_TRACER_LIB} -I${SRC_TRACER_INCL} -no-integrated-cpp -B${SRC_TRACER_WRAPPER}"

export LIBS="${LIBS} -lsrc_tracer"

# use -lzstd for zstd trace compression in fork
if grep "^\s*#define TRACE_USE_FORK" "${SRC_TRACER_INCL}/src_tracer/constants.h"
then
    export LIBS="${LIBS} -lzstd"
fi
