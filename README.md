# Source Tracer

This is a draft of a control flow tracer based on source code instrumentation with a low overhead.
When running instrumented software, the trace is written into a file `cflow_file.txt`.
The format is basically one character (plus an optional number)
for each source code block on the trace.
For accurate retracing, `trace_replay.py` uses symbolic execution.

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
* angr for symbolic execution

## Trace Format

Each element consists of one capital letter + an optional hex num in lower case.
Elements are written sequentially without any separator.

| Macro                   | Emits     | Explanation                                             |
|-------------------------|-----------|---------------------------------------------------------|
| `_FUNC_INST(num)`       | `C` + num | Function call, use `num` to distinguish functions       |
| `_IF_INST`              | `I`       | The if-branch of an if-clause is taken                  |
| `_ELSE_INST`            | `E`       | The else-branch of an if-clause is taken                |
| `_SWITCH_INST(num)`     | `S` + num | Jump to case indicated with `num` in a switch-clause    |
| `_LOOP_START(id)`       | `L`       | Beginning of a loop (for, while etc.)                   |
| `_LOOP_BODY(id)`        |           | Loop iteration, nothing is emitted                      |
| `_LOOP_END(id)`         | `P` + num | End of a loop, `num` indicates the number of iterations |
| `_CFLOW_INIT(filename)` |           | Initialize, write trace to `filename`                   |
| `_CFLOW_CLEANUP`        |           | Close the cflow tracer                                  |

The macros are written into the source code. For an example instrumentation, see `checksum_inst.c`
and the original `checksum.c`. A example trace is `C1EC2LP2I`, which has a sub-trace `C2LP2`.

## Example `checksum.c`

* Start with `checksum.c`
* Instrument it, see `checksum_inst.c`
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
  python trace_replay.py checksum_inst main C1EC2LP2I
  python trace_replay.py checksum_inst checksum C2LP2
  ```
