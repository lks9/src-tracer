
# Maxbuggy example

* `maxbuggy.c` (uninstrumented, buggy version)
* `maxbuggy_assert.c` (uninstrumented with assertion, buggy version)
* `maxfixed_assert.c` (uninstrumented with assertion, fixed version)
* `random_arrarys.h` (100 random-generated input arrays for max)

## Prerequisites

* See installation instructions in top-level README.md.

* CBMC (I used version 5.95.1)

## Compilation

* First run the pre-processor
  ```
  cpp -D_CBMC_MODE -I../../include maxbuggy_assert.c -o maxbuggy_cbmc.c
  ```
* Instrument it (the pre-processed version)
  ```
  python ../../instrumenter.py maxbuggy_cbmc.c --record max --close
  ```
* Compile for recording with `_TRACE_MODE`
  ```
  gcc -D_TRACE_MODE -O3 -I../../include -L../../lib maxbuggy_cbmc.c -o maxbuggy_trace -lsrc_tracer
  ```

## Recording
  ```
  ./maxbuggy_trace
  ```
  Now there should be 100 `*maxbuggy_assert.c.trace` files containing traces.

## Converting the Trace Format
  ```
  for tracefile in *maxbuggy_assert.c.trace
    do
      python ../../trace_to_array.py ${tracefile} -o ${tracefile}.c
    done
  ```
## Retro AC with CBMC
  ```
  for tracefile in *maxbuggy_assert.c.trace
    do
      cbmc -D_CBMC_MODE -I../../include ${tracefile}.c maxbuggy_cbmc.c --function max
    done
  ```

## Fixed Version

Now, do the same (instrumentation, compiling, recording, retro assertion checking)
with `maxfixed_assert.c`. There, the bug is fixed, and there are no longer any assertion
violations or `POSSIBLY_VIOLATED` results.

## Results

| Version                     | buggy | buggy  | fixed | fixed  |
|-----------------------------|-------|--------|-------|--------|
| Subtrace of                 |`max()`|`proc()`|`max()`|`proc()`|
| Trace count                 |  100  |  100   |  100  |  100   |
| `VERIFICATION FAILED`       |   83  |   83   |    0  |    0   |
| `VERIFICATION SUCCESFUL`    |   17  |   17   |  100  |  100   |
