#include <stdio.h>

int check(int i) {
    // if (i > 0)
    //     return 0;
    // else if (i == 0)
    //     return 2;
    // else
    //     return 1;
    switch(i) {
        case 0: return 0;
                break;
        case '1': return 1;
                break;
        case 2: return 2;
                break;
        case 67:return 67;
                break;
    }
}

int main(int argc, char** argv) {
    if (argc < 2)
        return -1;
    // int i = atoi(argv[1]);
    int i = argv[1][0];
    return check(i);
}
