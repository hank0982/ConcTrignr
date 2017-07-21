#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <math.h>

// int check(char* str) {
//     // switch(atoi(str)) {
//     //     case 1: return 1;
//     //     case 2: return 2;
//     //     case 3: return 3;
//     //     case 0: return 0;
//     // }
//     // char i = str[1];
//     if (str[0] > 60)
//         return 1;
//     else if(str[0] > 80)
//         return 2;
//     else
//         return 0;
// }

// int fake(char i) {
//     return i;
// }

int check(char* str) {
    // char i = string[0];
    double i = str[0] - '0', j = str[1] - '0';
    // double i, j;
    if ((i * i + j * j) / (2 * i * j) < 0.5)
        return 1;
    else
        return 0;
}

int main(int argc, char** argv) {
    // if (argc < 2)
    //     return -1;
    // // int i = atoi(argv[1]);
    // // int i = argv[1][0];
    // // return check(argv[1]);
    // if (argv[1][0] > '1')
    //     return 1;
    // else
    //     return 0;

    // int i = '0';
    // // read(0, &i, 1);
    // // printf("%d\n", i);

    // while (1);

    // switch (i) {
    //     case '0': return 0;
    //     case '1': return 1;
    //     case '2': return 2;
    //     default: return -1;
    // }
    char* str;
    return check(argv[1]);
}
