# Records and Analysis

[@Neil Zhao](https://github.com/zzrcxb)

## 1. Array

### a. Test program

```c
#include <stdio.h>

int check(int i) {
    int a[] = {1, 2, 3, 4, 5, 6};

    if (a[i] > 1) {
        a[i] = 0;
        return 1;
    }
    else {
        return 0;
    }

}

int main(int argc, char**argv) {
    int i = atoi(argv[1]);

    return check(i);
}
```

angr results:


```shell
➜  ConcTriton git:(master) ✗ python angr_run.py -r -s2 -C0 -l1 programs/array.c
WARNING | 2017-08-20 05:56:35,485 | claripy | Claripy is setting the recursion limit to 15000. If Python segfaults, I am sorry.

[*] Compiling...
gcc -o programs/a.out programs/array.c
[*] Compile completed

[*] Analysing...
WARNING | 2017-08-20 05:56:38,599 | simuvex.engine.successors | Exit state has over 257 possible solutions. Likely unconstrained; skipping. <BV64 mem_1fffeff50_22_64{UNINITIALIZED}>
[*] Paths found: 2
[+] New Input: 9 | ASCII: 57
[+] New Input: 6 | ASCII: 54
[*] Analysis completed

[*] Result 1:
Calling: programs/a.out 9
return value:-11

[*] Result 2:
Calling: programs/a.out 6
return value:1

Coverage: 50.00%                                                      
```

Triton results:

```shell
➜  ConcTriton git:(master) ✗ make triton P="a.out 1"                                  
=== Using Triton ===                                          
/home/neil/Triton/build/triton triton_run.py programs/a.out 1 
Before start analysis                                         
Before run program                                            
[+] Take Snapshot                                             
[+] In main                                                   
[+] In main() we set :                                        
Input data      [0x7fffdcabb754] = 49 1                       
[+] Exit point                                                
[]                                                            
Symbolic variables: {0L: SymVar_0:8}                          
input.bound 0                                                 
[+] Done !                                                    
```

KLEE test case:

```c
#include <stdio.h>

int check(char* s) {
    int a[] = {1, 2, 3, 4, 5, 6};
    int i = atoi(s);

    if (a[i] > 6) {
        a[i] = 1;
        return 1;
    }
    else {
        return 0;
    }
}

int main(int argc, char** argv) {
    char i[2];
    klee_make_symbolic(&i, sizeof(i), "i");
    klee_assume(i[1] == '\0');

    return check(i);
}
```



KLEE results:

```shell
➜  ~ clang -emit-llvm -c -g ConcTrignr/programs/array_klee.c
ConcTrignr/programs/array_klee.c:5:13: warning: implicit declaration of function 'atoi' is invalid in C99 [-Wimplicit-function-declaration]
    int i = atoi(s);
            ^
ConcTrignr/programs/array_klee.c:18:5: warning: implicit declaration of function 'klee_make_symbolic' is invalid in C99 [-Wimplicit-function-declaration]
    klee_make_symbolic(&i, sizeof(i), "i");
    ^
ConcTrignr/programs/array_klee.c:19:5: warning: implicit declaration of function 'klee_assume' is invalid in C99 [-Wimplicit-function-declaration]
    klee_assume(i[1] == '\0');
    ^
3 warnings generated.
➜  ~ klee  --libc=uclibc -posix-runtime array_klee.bc
KLEE: NOTE: Using klee-uclibc : /home/klee/klee_build/klee/Release+Debug+Asserts/lib/klee-uclibc.bca
KLEE: NOTE: Using model: /home/klee/klee_build/klee/Release+Debug+Asserts/lib/libkleeRuntimePOSIX.bca
KLEE: output directory is "/home/klee/klee-out-11"
KLEE: Using STP solver backend
KLEE: WARNING ONCE: calling external: syscall(16, 0, 21505, 49392960) at /home/klee/klee_src/runtime/POSIX/fd.c:1044
KLEE: WARNING ONCE: calling __user_main with extra arguments.
KLEE: WARNING ONCE: Alignment of memory from call "malloc" is not modelled. Using alignment of 8.
KLEE: ERROR: /home/klee/ConcTrignr/programs/array_klee.c:7: memory error: out of bound pointer
KLEE: NOTE: now ignoring this error at this location

KLEE: done: total instructions = 6113
KLEE: done: completed paths = 8
KLEE: done: generated tests = 7
➜  ~ python get_res.py 7
ktest-tool --write-ints klee-last/test000001.ktest
ktest file : 'klee-last/test000001.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'\x0b\x00'
ktest-tool --write-ints klee-last/test000002.ktest
ktest file : 'klee-last/test000002.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'-\x00'
ktest-tool --write-ints klee-last/test000003.ktest
ktest file : 'klee-last/test000003.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'+\x00'
ktest-tool --write-ints klee-last/test000004.ktest
ktest file : 'klee-last/test000004.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'\x00\x00'
ktest-tool --write-ints klee-last/test000005.ktest
ktest file : 'klee-last/test000005.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'6\x00'
ktest-tool --write-ints klee-last/test000006.ktest
ktest file : 'klee-last/test000006.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'A\x00'
ktest-tool --write-ints klee-last/test000007.ktest
ktest file : 'klee-last/test000007.ktest'
args       : ['array_klee.bc']
num objects: 2
object    0: name: b'model_version'
object    0: size: 4
object    0: data: 1
object    1: name: b'i'
object    1: size: 2
object    1: data: b'0\x00'
```

As we can see, angr generated two "illegal" test cases. Triton could not solve this kind of problem. KLEE gave us a myriad of test cases which are mostly incorrect.

### b. Analysis

Function calling stack looks like the following figure.
 <center><img src="../4/Call_stack_layout.svg.png" height="350"></center>

There is no way to know the size of the static array, because EFL binary files don't contain any information about how large the array is. Symbolic constraint solver engine cannot find an appropriate way to prevent the engine from visiting memory outside of the array. Therefore, it may generate test cases that can lead to **Segmentation Fault**.

When it comes to dynamic array stored in the lheap, solver engine is still incapable of retrieving the size information.  By leveraging predefined data structures and high-level classes or compling program with debugging symbols, we could obtain the size information of dynamic array. However, test tools support limited standard data structures and classes, such as vector in C++, to access the size information. In terms of user-defined data structures or classes, testers are required to provide extra details indicating the storing location of the size information.

(The only way we can reserve size information is define some structures or some high-level classes or compile sources into programs with debugging symbols. Such as vector supported by C++. But test tools can only support these standard structures or classes which tools know where they can reach size information. As for some user-defined structures or classes, testers must provide some extra information about where the size information is stored.)

On the other hand, if we can analyze programs' source code directly, all information we need can be retrieved. Unfortunately, KLEE failed the array challenge. It generates many index-out-of-bound exceptions, which may lead to segmentation fault.

In order to solve this challenge, we can change the binary file format to contain more information. Alternatively, our tool can use information contained in the source code correctly. Otherwise, no existing tool can solve this challenge theoretically. The best thing programmer can do is to have a good programming habit of always checking index before visiting elements of an array. We can improve the test program as follows:

```c
int main(int argc, char**argv) {
    int a[] = {1, 2, 3, 4, 5, 6};
    int i = atoi(argv[1]);

    if (i >= 0 && i < 6 && a[i] > 6)
        return 1;
    else
        return 0;
}
```

Even this program can only reach the "return 0" statement, but angr said it found two paths. I am still investigating causes. But at least it won't generate test cases can crash the program.

```shell
➜  ConcTriton git:(master) ✗ python angr_run.py -r -s2 -C0 -l1 programs/array.c
WARNING | 2017-08-20 05:55:46,196 | claripy | Claripy is setting the recursion limit to 15000. If Python segfaults, I am sorry.

[*] Compiling...
gcc -o programs/a.out programs/array.c
[*] Compile completed

[*] Analysing...
[*] Paths found: 2
[+] New Input: 8 | ASCII: 56
[+] New Input: 3 | ASCII: 51
[*] Analysis completed

[*] Result 1:
Calling: programs/a.out 8
return value:0

[*] Result 2:
Calling: programs/a.out 3
return value:0

Coverage: 50.00%                                           
```

And here is KLEE's output:

```shell
➜  ~   python get_res.py 2                        
ktest-tool --write-ints klee-last/test000001.ktest
ktest file : 'klee-last/test000001.ktest'         
args       : ['array_klee.bc']                    
num objects: 1                                    
object    0: name: b'i'                           
object    0: size: 4                              
object    0: data: 6                              
ktest-tool --write-ints klee-last/test000002.ktest
ktest file : 'klee-last/test000002.ktest'         
args       : ['array_klee.bc']                    
num objects: 1                                    
object    0: name: b'i'                           
object    0: size: 4                              
object    0: data: 0                              
```



## 2. Multithreading

### a. Test program

```c
#include <pthread.h>
#include <time.h>
#include <unistd.h>


void* inc(void* i) {
    long long* j = (long long*)i;
    unsigned long start = (unsigned long)time(NULL);

    while ((unsigned long)time(NULL) - start < 2)
        *j += 1;
}

void* dec(void* i) {
    long long* j = (long long*)i;
    unsigned long start = (unsigned long)time(NULL);

    while ((unsigned long)time(NULL) - start < 2)
        *j -= 1;
}

int check(long long* i) {
    pthread_t thread1, thread2;
    int rc1 = pthread_create(&thread1, NULL, inc, (void*)i);
    int rc2 = pthread_create(&thread2, NULL, dec, (void*)i);
    int flag;

    sleep(1);
    printf("%lld", *i);

    if (*i > 0)
        flag = 1;
    else
        flag = 0;

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return flag;
}

int main(int argc, char** argv) {
    long long i = atoi(argv[1]);

    return check(&i);
}
```

If you compile these and run the program several times, you may get something like this:

```shell
➜  ConcTriton git:(master) ✗ gcc -o programs/m.out programs/multi_thread.c -lpthread
programs/multi_thread.c: In function 'check':
programs/multi_thread.c:29:5: warning: incompatible implicit declaration of built-in function 'printf' [enabled by default]
     printf("%lld", *i);
     ^
➜  ConcTriton git:(master) ✗ programs/m.out 0
24244245
➜  ConcTriton git:(master) ✗ programs/m.out 0
13134895
➜  ConcTriton git:(master) ✗ programs/m.out 0
-217098
```

Even you keep passing 0 to this program, its output is almost random. You cannot even find any pattern from those outputs. Because of uncertainty of the system, we will get a different output each time. Therefore, this challenge cannot be solved theoretically. 

angr encountered some errors while stepping. Its IP was set to 0x0 after several steps. I've opened an issue on GitHub and I'm still waiting for an official reply.

```python
In [1]: while len(pg.active) > 0:
            print pg.active[0].state.regs.ip
            pg.step()
Out[1]:
<BV64 0x400560>
<BV64 0x400530>
<BV64 0x50000b0>
<BV64 0x4006a0>
<BV64 0x4004f0>
<BV64 0x400505>
<BV64 0x4006d3>
<BV64 0x4006d8>
<BV64 0x400620>
<BV64 0x400648>
<BV64 0x4005c0>
<BV64 0x4005e2>
<BV64 0x4006ed>
<BV64 0x4006f6>
<BV64 0x50000c0>
<BV64 0x400653>
<BV64 0x400520>
<BV64 0x5000100>
<BV64 0x40064d>
<BV64 0x0>
<BV64 0x0>
```



Triton used almost 4G memory and got nothing.

As for KLEE:

```shell
➜  ~ klee  --libc=uclibc -posix-runtime multi_thread_klee.bc
KLEE: NOTE: Using klee-uclibc : /home/klee/klee_build/klee/Release+Debug+Asserts/lib/klee-uclibc.bca
KLEE: NOTE: Using model: /home/klee/klee_build/klee/Release+Debug+Asserts/lib/libkleeRuntimePOSIX.bca
KLEE: output directory is "/home/klee/klee-out-9"
KLEE: Using STP solver backend
KLEE: WARNING: undefined reference to function: pthread_create
KLEE: WARNING: undefined reference to function: pthread_join
KLEE: WARNING ONCE: calling external: syscall(16, 0, 21505, 46710576) at /home/klee/klee_src/runtime/POSIX/fd.c:1044
KLEE: WARNING ONCE: calling __user_main with extra arguments.
KLEE: WARNING ONCE: Alignment of memory from call "malloc" is not modelled. Using alignment of 8.
KLEE: WARNING ONCE: calling external: pthread_create(47000016, 0, 28000336, 44456288) at /home/klee/ConcTrignr/programs/multi_thread_klee.c:24
KLEE: ERROR: /home/klee/ConcTrignr/programs/multi_thread_klee.c:25: failed external call: pthread_create
KLEE: NOTE: now ignoring this error at this location
[1]    1632 segmentation fault (core dumped)  klee --libc=uclibc -posix-runtime multi_thread_klee.bc
```

It seems like KLEE doesn't support pthread_create yet, which was mentioned by some forums earlier. However, according to Parallel Symbolic Execution for Automated Real-World Software Testing listed in the documentation of KLEE, there is an extension called cloud9 which could solve this challenge. Although it is a potential solution, it is not under maintenance.

### b. Analysis

// TODO

## 3. Overflow

### a. Test program

```c
#include <stdio.h>

int check(int b) {
    int a = 2147483640;
    int c = 3;

    if (c * b < 0 && b > 0)
        return 1;
    else if (a + b < 0 && b > 0)
        return 2;
    else
        return 0;
}

int main(int argc, char** argv) {
    int i = atoi(argv[1]);

    return check(i);
}
```

angr output

```shell
➜  ConcTriton git:(master) ✗ python angr_run.py -r -s3 -C0 -l10 programs/overflow.c
WARNING | 2017-08-21 05:26:10,852 | claripy | Claripy is setting the recursion limit to 15000. If Python segfaults, I am sorry.



[*] Compiling...
gcc -o programs/o.out programs/overflow.c
[*] Compile completed

[*] Analysing...
[*] Paths found: 4
[+] New Input:  0<0000000 | ASCII: 0 48 60 48 48 48 48 48 48 48
[+] New Input: -8Z  ☺→§o | ASCII: 45 56 90 32 195 0 1 26 21 111
[+] New Input: 892977170= | ASCII: 56 57 50 57 55 55 49 55 48 61
[+] New Input: 9u■q§9 | ASCII: 57 166 117 22 166 244 113 175 21 57
[*] Analysis completed

[*] Result 1:
Calling: programs/o.out 0<0000000
return value:0

[*] Result 2:
Calling: programs/o.out -8Z ☺→§o
return value:0

[*] Result 3:
Calling: programs/o.out 892977170=
return value:1

[*] Result 4:
Calling: programs/o.out 9u■q§9
return value:2

Coverage: 100.00%
```

Triton output

```shell
➜  ConcTriton git:(master) ✗ make triton P="o.out 0000000000"
echo "=== Using Triton ==="
=== Using Triton ===
/home/neil/Triton/build/triton triton_run.py programs/o.out 0000000000
Before start analysis
Before run program
[+] Take Snapshot
[+] In main
[+] In main() we set :


48 0     48 0    48 0    48 0    48 0    48 0    48 0    48 0    48 0    48 0    48 0    48 0
[+] Exit point
[[2711L, 4195674L, 4195661L], [2731L, 4195699L, 4195686L]]
input.bound 0
[+] Restore snapshot
[+] In main
[+] In main() we set :
61  111  79  66  0  64  38  32  183  89  195  25
= o O B   @ &    Y  ↓

[+] Exit point
[[1723L, 4195674L, 4195661L], [1743L, 4195699L, 4195686L]]
input.bound 2
[+] Restore snapshot
[+] In main
[+] In main() we set :
55  254  229  79  245  194  139  99  37  219  49  52
7   O    c %  1 4

[+] Exit point
[[1825L, 4195674L, 4195661L], [1845L, 4195699L, 4195686L]]
input.bound 1
[+] Restore snapshot
[+] In main
[+] In main() we set :
64  254  229  79  245  194  139  99  37  219  49  52
@   O    c %  1 4

[+] Exit point
[[1723L, 4195674L, 4195661L], [1743L, 4195699L, 4195686L]]
input.bound 2
[+] Done !
```

KLEE output:

```shell
➜  ~ clang -emit-llvm -c -g ConcTrignr/programs/overflow_klee.c
ConcTrignr/programs/overflow_klee.c:6:13: warning: implicit declaration of function 'atoi' is invalid in C99 [-Wimplicit-function-declaration]
    int b = atoi(s);
            ^
ConcTrignr/programs/overflow_klee.c:19:5: warning: implicit declaration of function 'klee_make_symbolic' is invalid in C99 [-Wimplicit-function-declaration]
    klee_make_symbolic(&i, sizeof(i), "i");
    ^
ConcTrignr/programs/overflow_klee.c:20:5: warning: implicit declaration of function 'klee_assume' is invalid in C99 [-Wimplicit-function-declaration]
    klee_assume(i[10] == '\0');
    ^
3 warnings generated.
➜  ~ klee  --libc=uclibc -posix-runtime overflow_klee.bc
KLEE: NOTE: Using klee-uclibc : /home/klee/klee_build/klee/Release+Debug+Asserts/lib/klee-uclibc.bca
KLEE: NOTE: Using model: /home/klee/klee_build/klee/Release+Debug+Asserts/lib/libkleeRuntimePOSIX.bca
KLEE: output directory is "/home/klee/klee-out-12"
KLEE: Using STP solver backend
KLEE: WARNING ONCE: calling external: syscall(16, 0, 21505, 44119728) at /home/klee/klee_src/runtime/POSIX/fd.c:1044
KLEE: WARNING ONCE: calling __user_main with extra arguments.
KLEE: WARNING ONCE: Alignment of memory from call "malloc" is not modelled. Using alignment of 8.

KLEE: done: total instructions = 1040827
KLEE: done: completed paths = 14701
KLEE: done: generated tests = 14701
➜  ~ python run_program.py 14701 ConcTrignr/programs/overflow_klee.c
[+] Compiling...
[+] Compilied
Return values set: {0}
Total: 1
```

KLEE consumed a great amount of time to generate many test cases. But the results are frustrating, these test cases can only trigger one branch. So we come to the conclusion that only angr can handle this challenge properly.

### b. Analysis

// TODO

## 4. Float-point Number



## 5. Signed & Unsigned



## 6. File Reading



