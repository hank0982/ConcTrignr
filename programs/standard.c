#include <stdio.h>

int check(int i) {
    int arr[] = {1, 2, 3, 4, 5, 6};

    if (arr[i] > 10)
        return 1;
    else
        return 0;
}

int main(int argc, char** argv) {
    // int i = atoi(argv[1]);
    // if (argc != 2)
    //     return 2;
    // else
    //     return check(argv[1]);
    int i;

    return check(i);
}