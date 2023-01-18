#include <stdio.h>

int main(int argc, char **argv) {
    switch (argc) {
      case 0:
        printf("h");
      case 1:
        printf("a");
      case 2:
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
}
