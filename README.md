# Source Tracer

This is a draft of a control flow tracer based on source code instrumentation with a low overhead.
Instrument your software with `instrumenter.py`. When running instrumented software, the trace is written into a file.
The format is basically one character (plus an optional number)
for each source code block on the trace.
For accurate retracing, `retrace.py` uses symbolic execution.

## Which Software to Trace

Any software which is written in C/C++, with the source code available.

## Dependencies
### For the Instrumentation

* python3
* libclang (`pip install libclang`)

### For the Trace Recording

* C compiler (or your build system at choice) to compile the instrumented software

### For the Symbolic Replayer

* C compiler (or your build system at choice) to compile the instrumented software
* python3
* [angr](https://angr.io) for symbolic execution (`pip install angr`)

## Setup

* Run make
   ```
   make
   ```
* TODO

## Example `checksum.c`

* First run the pre-processor
  ```
  cd examples/
  cpp -I../include checksum.c -o checksum_inst.c
  ```
* Instrument it (the pre-processed version)
  ```
  python ../instrumenter.py checksum_inst.c
  ```
  For a list of functions together with the `num` generated by the instrumenter,
  have a look at the newly created `functions_database.db`.
### Recording
* Compile it with `_TRACE_MODE` (you might also want different compiler optimizations for recording/replaying)
  ```
  gcc -D_TRACE_MODE -O3 -I../include -L../lib checksum_inst.c -o checksum_trace -lsrc_tracer
  ```
* Run it (replace `42` to get another trace) 
  ```
  ./checksum_trace 42
  ```
  The name of the recorded trace corresponds to the current time, e.g. `2023-04-28-143402-checksum.c.trace`.
* Display the trace (replace the trace name with the correct one!)
  ```
  python ../print_trace.py 2023-04-28-143402-checksum.c.trace
  ```
### Retracing
* Compile it with `_RETRACE_MODE` (you might also want different compiler optimizations for recording/replaying)
  ```
  gcc -D_RETRACE_MODE -g -I../include -L../lib checksum_inst.c -o checksum_retrace -lsrc_tracer
  ```
* Retrace it (use `python -i` to work with the traced `state` in the interactive shell)
  ```
  python ../retrace.py checksum_retrace 2023-04-28-143402-checksum.c.trace
  echo "F1TTN" > sub.trace.txt
  python ../retrace.py checksum_retrace sub.trace.txt
  ```
  The last one just retraces function `checksum`.

## Busybox with musl-libc

Tested: busybox v1.34 and musl v1.2.3

* Set flags and configure musl:

  ```bash
  export SRC_TRACER_DIR=<path-to>/src-tracer/
  export CFLAGS="-Wno-error -L${SRC_TRACER_DIR}/lib -I${SRC_TRACER_DIR}/include -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export SRC_TRACER=""

  ./configure
  ```

* Patch musl: In `config.mak` add `-lsrc_tracer` to `LIBCC`.
In `src/string/strlen.c`, `src/string/strchrnul.c` and
`src/string/stpcpy.c` replace `#ifdef __GNUC__` by `#if false`.
The latter is a workaround for angr to ignore address alignments (see angr/angr#3883).

* Make (text trace mode) and install:
  ```bash
  export SRC_TRACER="-D_TRACE_MODE"
  make
  sudo make install
  ```

* Follow steps 2 and 3 from https://www.openwall.com/lists/musl/2014/08/08/13
to configure busybox to compile statically linked against musl.

* Before you run `make`, add `src_tracer` to the `CONFIG_EXTRA_LDLIBS`
in `.config`:

  ```
  CONFIG_EXTRA_LDLIBS="src_tracer"
  ```

* Run:

  ```bash
  make
  ```

  When you get a lot of

  ```
  warning: ISO C90 forbids mixed declarations and code [-Wdeclaration-after-statement]
  ```
  then the instrumatation is working as it should! You could silent these by
  commenting out the following line in `Makefile.flags`:
  ```
  CFLAGS += $(call cc-option,-Wdeclaration-after-statement,)
  ```

* Once we compiled it successfully, you don't need the stripped version.
  So just rename:

  ```bash
  mv busybox_unstripped busybox_trace
  ```

* Et voila!

* To record some trace:

  ```bash
  ./busybox_trace echo hello
  ```

  The trace will be somewhere, in my case `~/.src_tracer/2023-04-28-153959-appletlib.c.trace`.

* Print the trace into a file:

  ```bash
  ${SRC_TRACER_DIR}/print_trace.py ~/.src_tracer/2023-04-28-153959-appletlib.c.trace > ~/.src_tracer/echo.trace.txt
  ```

* Now we are back to compile musl in retrace mode (same `CFLAGS` but with `-mbranch-cost=5` to the maximum
  because state splitting _really_ slows down retracing):

  ```bash
  export SRC_TRACER_DIR=<path-to>/src-tracer/
  export CFLAGS="-Wno-error -O3 -mbranch-cost=5 -L${SRC_TRACER_DIR}/lib -I${SRC_TRACER_DIR}/include -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export SRC_TRACER=""
  ./configure
  ```
  Then in `config.mak` add `-lsrc_tracer` to `LIBCC`.
  ```bash
  export SRC_TRACER="-D_RETRACE_MODE"
  make clean
  make
  sudo make install
  ```

* Compile busybox in retrace mode:

  ```bash
  make clean
  make
  mv busybox_unstripped busybox_retrace
  ```

* Replay trace:

  ```bash
  ${SRC_TRACER_DIR}/retrace.py busybox_retrace ~/.src_tracer/echo.trace.txt
  ```

  Retracing took 42 min on my computer.

## Other Software

You can do it manually as for the `checksum.c` example.

For a more automatic way that works well with make scripts, make use of `cc_wrapper/`.

### Recording
* Set some envirenmental variables. There are some variations, for example you might also add `-save-temps` to `CFLAGS`.
  ```
  export SRC_TRACER_DIR=.........
  export CC="gcc"
  export CFLAGS="-Wno-error -L${SRC_TRACER_DIR}/lib -I${SRC_TRACER_DIR}/include -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export LIBS="-lsrc_tracer"
  export SRC_TRACER=""
  ```
* Now you can ./configure your project...
* You can copy the build directory here, if you want to reuse the configuration for retracing.
* Before the actual compilation:
  ```
  export SRC_TRACER="-D_TRACE_MODE"
  ```
* Then build your project with make, gcc, whatever

### Retracing
* Same envirenmental variables as before. Only if you want to change some variables (e.g. `CFLAGS` with `-g`) make sure
to set `SRC_TRACER=` (as empty string) before you `./configure` your project again.
* Before the actual compilation:
  ```
  export SRC_TRACER="-D_RETRACE_MODE"
  ```
* Then build your project with make, gcc, whatever

It can be a bit tricky to get the binary linking correctly,
make sure that the record/replay executable includes the record/replay
version of the app and its libraries.
