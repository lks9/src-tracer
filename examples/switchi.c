#include <stdio.h>

void foo(void) {}

int main(int argc, char **argv) {
    _RETRACE_ASSERT("not strange", argc < 5 );
    foo();
    switch (argc) {
      case 0:
        printf("h");
      case 1:
        printf("a");
      case 2:
        _RETRACE_ASSERT("h", argc != 0);
        _RETRACE_ASSERT("not strange2", argc < 5 );
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
    _RETRACE_ASSERT("s", argv[0][0] == 's');
}
