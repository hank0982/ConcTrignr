#include <stdio.h>

int main(int argc, char** argv) {
    unsigned a = 80;
    int b = argv[1][0] - '0';

    if (b > a && b < 0)
        return 1;
    else
        return 0;
}