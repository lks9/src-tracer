#include <stdio.h>


int checksum (char *str) {
    int sum = 0;
    int i = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        sum = sum + str[i] - '0';
    }
    return sum;
}

int main (int argc, char **argv) {
    if (argc != 2) {
        return -1;
    } else {}

    char *string = argv[1];
    int sum = checksum(string);

    if ( sum % 2 == 0 ) {
        printf("The checksum of \"%s\" is even.\n", string);
    } else {
        printf("The checksum \"%s\" is odd.\n", string);
    }

    return 0;
}
