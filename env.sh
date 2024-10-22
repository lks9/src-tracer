#!/usr/bin/env bash

# set up all the variables for the instrumentation

# if SRC_TRACER_DIR is not set, set it
if [ -z "${SRC_TRACER_DIR}" ];
then
    BASE_DIR="$( dirname "${BASH_SOURCE[0]}" )"
    export SRC_TRACER_DIR="$( realpath -e "${BASE_DIR}" )"
fi

# the other paths just depend on SRC_TRACER_DIR
export SRC_TRACER_INCL="${SRC_TRACER_DIR}/include/"
export SRC_TRACER_LIB="${SRC_TRACER_DIR}/lib/"
export SRC_TRACER_WRAPPER="${SRC_TRACER_DIR}/cc_wrapper/"

# set the PATH so we directly execute the python scripts
export PATH=$PATH:${SRC_TRACER_DIR}
