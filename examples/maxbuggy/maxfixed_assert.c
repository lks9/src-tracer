#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "random_arrays.h"

#include "src_tracer/ghost.h"

int max (int len, int a[len]) {
   int m = a[0];
   /* assumption here */
   for (int k=0; k < len; k += 1) {
      if (m < a[k]) { m = a[k]; }
   }
   RETRO_ASSERT((0 >= len || m >= a[0])
             && (1 >= len || m >= a[1])
             && (2 >= len || m >= a[2])
             && (3 >= len || m >= a[3]));
   // for CBMC we could use the forall quantification...
   //assert( __CPROVER_forall { int i; !(0 <= i && i < len) || m >= a[i] } );
   return m;
}

#define SOME_CODE /* nothing here */

void proc(int len, int a[len]) {
   printf("max: %d\n", max(len, a));

   for (int j=1; j < len; j++) {
      if (a[j-1] < a[j]) {
         SOME_CODE;
      }
   }
}

int main(int argc, char **argv) {
   for (int k=0; k < ARRAY_COUNT; k++) {
      proc(arrs[k].len, arrs[k].arr);
   }
}
