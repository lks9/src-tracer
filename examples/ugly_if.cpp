#include <stdbool.h>
#include <stdio.h>
constexpr int foo (void) {
    return 43;
}

int main (int argc, char** argv) {
  if (bool b = true)
    printf("Yay!\n");
  else {
    printf("Ney!\n");
  }

  if (true)
      return foo();
  else if (false) {}
}

