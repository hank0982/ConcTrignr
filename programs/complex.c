#include <stdio.h>

int check(int i) {
    if (i > 97)
        return 0;
    else if (i == 65)
        return 2;
    else
        return 1;
}

int main(int argc, char** argv) {
    if (argc < 2)
        return -1;
    // int i = atoi(argv[1]);
    int i = argv[1][0];
    return check(i);
}
