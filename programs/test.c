
int check() {
    return 1;
}

int main(int argc, char** argv) {
    // int i = atoi(argv[1]);
    int i = argv[1][0];
    int j = argv[1][1];

    // printf("%s", argv[1]);

    switch(i) {
        case 1: return 1;
        case '2': switch(j) {
            case '1': return 2;
            case '2': return 1;
            default: return 0;
        }
        case '3': return 3;
        default: return 0;
    }
}
