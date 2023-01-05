#include <stdio.h>
#include "cflow_inst.h"

int checksum (char *str) { _FUNC(2)
    int sum = 0;
    _LOOP_START(1) for (int i = 0; str[i] != '\0'; i++) { _LOOP_BODY(1)
        sum = sum + str[i] - '0';
    } _LOOP_END(1)
    return sum;
}

int main_original (int argc, char **argv) { _FUNC(1)
    if (argc != 2) { _IF
        return -1;
    } else { _ELSE }

    char *string = argv[1];
    int sum = checksum(string);

    if ( sum % 2 == 0 ) { _IF
        printf("The checksum of \"%s\" is even.\n", string);
    } else { _ELSE
        printf("The checksum \"%s\" is odd.\n", string);
    }

    return 0;
}

int main (int argc, char **argv) {
    _cflow_open("checksum_cflow_trace.txt");
    int retval = main_original(argc, argv);
    _cflow_close();
    return retval;
}
