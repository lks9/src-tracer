int a;

void foo(int i, int b, int q) {
    switch (i) {
      case 0:
          a = 1;
    }
    if ( b ) {
        // do nothing
    } else if ( q ) {
        a = 0;
    }
}

int main(int argc, char **argv) {
    foo(0, 1, 1);
    foo(1, 0, 1);
    return 0;
}
