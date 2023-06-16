#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "random_arrays.h"

int max (int len, int a[len]) {
   int m = a[0];
   /* assumption here */
   for (int k=0; k < len; k++) {
      if (m < a[k]) { m = a[k++]; }
   }
   /* assertion here */
   return m;
}

#define SOME_CODE /* nothing here */

void process_array(int len, int a[len]) {
   printf("max: %d\n", max(len, a));

   for (int j=1; j < len; j++) {
      if (a[j-1] < a[j]) {
         SOME_CODE;
      }
   }
}

int main(int argc, char **argv) {
   for (int k=0; k < ARRAY_COUNT; k++) {
      process_array(arrs[k].len, arrs[k].arr);
   }
}
