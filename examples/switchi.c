#include <stdio.h>
#include <src_tracer/ghost.h>
void foo(void) {}

int main(int argc, char **argv) {
    PROPOSE("not strange", argc < 5 );
    foo();
    switch (argc) {
      case 0:
        printf("h");
      case 1:
        printf("a");
      case 2:
        ASSERT( argc != 0);
        PROPOSE("not strange2", argc < 5 );
        printf("l");
        printf("l");
      case 3:
      case 4:
        printf("o");
        printf("!\n");
        break;
      default:
      case 17:
        printf("strange 17\n");
    }
    PROPOSE("s", argv[0][0] == 's');
    int x = argc < 3 ? 0 : 1;
}
