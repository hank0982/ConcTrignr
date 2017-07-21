#include <vector>

using namespace std;

int check(char* str) {
    static const int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<int> v(arr, arr + sizeof(arr) / sizeof(arr[0]));
    
    switch(str[0]) {
        case '1': return 1;
        case '2': return 2;
        default: return 0;
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        return -1;
    }

    return check(argv[1]);
}