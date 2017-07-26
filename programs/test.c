#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

int check() {
    return 1;
}

int main(int argc, char** argv) {
    int i = atoi(argv[1]);
    // int i = argv[1][0];

    if (i % 2)
        return check();
    else
        return 0;
}
