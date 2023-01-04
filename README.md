# Source Tracer

This is a draft of a control flow tracer based on source code instrumentation with a low overhead.
When running instrumented software, the trace is written into a file `cflow_file.txt`.
The format is basically one character (plus an optional number)
for each source code block on the trace.
For accurate retracing, `replay_trace.py` uses symbolic execution.

## Which Software to Trace

Any software which is written in C, with the source code available.

## Dependencies
### For the Instrumentation

* Any source code editor

(Automatic source instrumentation is currently work in progress, so
help yourself by doing it manually)

### For the Trace Recording

* C compiler (or your build system at choice) to compile the instrumented software

### For the Symbolic Replayer

* C compiler (or your build system at choice) to compile the instrumented software
* python3
* [angr](https://angr.io) for symbolic execution (`pip install angr`)

## Instrumentation

1. Add to each source file
   ```C
   #include "cflow_inst.h"
   ```
2. Add macros to the respective code blocks. A list of all macros is given below.

For an example instrumentation, see `checksum_inst.c`
and the original `checksum.c`.

## Trace Format

Each element consists of one capital letter + an optional hex `num` in lower case.
Elements are written sequentially without any separator.

| Macro                | Emits       | Explanation                                             |
|----------------------|-------------|---------------------------------------------------------|
| `_FUNC_INST(num)`    | `F` + `num` | Function call, use `num` to distinguish functions       |
| `_IF_INST`           | `I`         | The if-branch of an if-clause is taken                  |
| `_ELSE_INST`         | `E`         | The else-branch of an if-clause is taken                |
| `_SWITCH_INST(num)`  | `S` + `num` | Jump to case indicated with `num` in a switch-clause    |
| `_LOOP_START(id)`    | `L`         | Beginning of a loop (for, while etc.)                   |
| `_LOOP_BODY(id)`     |             | Loop iteration, nothing is emitted                      |
| `_LOOP_END(id)`      | `P` + `num` | End of a loop, `num` indicates the number of iterations |
| `_CFLOW_INIT(fname)` |             | Initialize, write trace to file named `fname`           |
| `_CFLOW_CLEANUP`     |             | Close the cflow tracer                                  |

The macros are written into the source code.
An example trace is `F1EF2LP2I`, which includes sub-traces, for example `F2LP2` or `LP2`.

## Example `checksum.c`

* Instrumentation is in `checksum_inst.c`
* Compile it
  ```
  gcc checksum_inst.c -o checksum_inst
  ```
* Run it
  ```
  ./checksum_inst 42
  ```
* Retrace it
  ```
  python replay_trace.py checksum_inst main F1EF2LP2I
  python replay_trace.py checksum_inst checksum F2LP2
  ```
