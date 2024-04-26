
# COUNT example

* `count.c`

## Prerequisites

* See installation instructions in top-level README.md.

* CBMC (I used version 5.95.1)

## Compilation

* First run the pre-processor
  ```
  cpp -D_CBMC_MODE -I../../include count.c -o count_cbmc.c
  ```
* Instrument it (the pre-processed version)
  ```
  python ../../instrumenter.py count_cbmc.c --record count --close
  ```
* Compile for recording with `_TRACE_MODE`
  ```
  gcc -D_TRACE_MODE -O3 -I../../include -L../../lib count_cbmc.c -o count_trace -lsrc_tracer
  ```

## Recording
  ```
  ./count_trace
  ```
  Now there should be 100 `*maxbuggy_assert.c.trace` files containing traces.

## Converting the Trace Format
  ```
  for tracefile in *count.c.trace
    do
      python ../../trace_to_array.py ${tracefile} -o count.c.trace.c
    done
  ```
## Retro AC with CBMC
  ```
  cbmc --paths lifo -D_CBMC_MODE -I../../include count.c.trace.c count_cbmc.c --function count
  ```

