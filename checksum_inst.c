#include <stdio.h>
#include "cflow_inst.h"

int checksum (char *str) { _FUNC_INST(2)
    int sum = 0;
    int i = 0;
    _LOOP_START(1) for (int i = 0; str[i] != '\0'; i++) { _LOOP_BODY(1)
        sum = sum + str[i] - '0';
    } _LOOP_END(1)
    return sum;
}

int main_original (int argc, char **argv) { _FUNC_INST(1)
    if (argc != 2) { _IF_INST
        return -1;
    } else { _ELSE_INST }

    char *string = argv[1];
    int sum = checksum(string);

    if ( sum % 2 == 0 ) { _IF_INST
        printf("The checksum of \"%s\" is even.\n", string);
    } else { _ELSE_INST
        printf("The checksum \"%s\" is odd.\n", string);
    }

    return 0;
}

int main (int argc, char **argv) {
    _CFLOW_INIT
    int retval = main_original(argc, argv);
    _CFLOW_CLEANUP
    return retval;
}
