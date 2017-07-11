#include <stdio.h>

int check(int i) {
    if (i < 0)
        return -1;
    else if (i == 0)
        return 0;
    else
        return 1;
}

int main(int argc, char** argv) {
    if (argc < 2)
        return -1;
    int i = atoi(argv[1]);
    return check(i);
}
