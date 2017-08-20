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

int check(int i) {
    int a[] = {1, 2, 3, 4, 5, 6};

    if (a[i] > 6) {
        a[i] = 0;
        return 1;
    }
    else {
        return 0;
    }
}

int main() {
    int i;
    klee_make_symbolic(&i, sizeof(i), "i");
    return check(i);
}
```



KLEE results:

```shell
ktest file : 'klee-last/test000001.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 6
ktest file : 'klee-last/test000002.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: -224
ktest file : 'klee-last/test000003.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 0
ktest file : 'klee-last/test000004.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: -216
ktest file : 'klee-last/test000005.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: -264
ktest file : 'klee-last/test000006.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 1500
ktest file : 'klee-last/test000007.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 2692
ktest file : 'klee-last/test000008.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 41404
ktest file : 'klee-last/test000009.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 6128
ktest file : 'klee-last/test000010.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 41792
ktest file : 'klee-last/test000011.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 42196
ktest file : 'klee-last/test000012.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 42308
ktest file : 'klee-last/test000013.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 42648
ktest file : 'klee-last/test000014.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 59212
ktest file : 'klee-last/test000015.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 61908
ktest file : 'klee-last/test000016.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 44428
ktest file : 'klee-last/test000017.ktest'
args       : ['array_klee.bc']
num objects: 1
object    0: name: b'i'
object    0: size: 4
object    0: data: 61992
ktest-tool --write-ints klee-last/test000001.ktest
ktest-tool --write-ints klee-last/test000002.ktest
ktest-tool --write-ints klee-last/test000003.ktest
ktest-tool --write-ints klee-last/test000004.ktest
ktest-tool --write-ints klee-last/test000005.ktest
ktest-tool --write-ints klee-last/test000006.ktest
ktest-tool --write-ints klee-last/test000007.ktest
ktest-tool --write-ints klee-last/test000008.ktest
ktest-tool --write-ints klee-last/test000009.ktest
ktest-tool --write-ints klee-last/test000010.ktest
ktest-tool --write-ints klee-last/test000011.ktest
ktest-tool --write-ints klee-last/test000012.ktest
ktest-tool --write-ints klee-last/test000013.ktest
ktest-tool --write-ints klee-last/test000014.ktest
ktest-tool --write-ints klee-last/test000015.ktest
ktest-tool --write-ints klee-last/test000016.ktest
ktest-tool --write-ints klee-last/test000017.ktest
```

As we can see, angr generated two "illegal" test cases, Triton could not solve this kind of  problem, and I don't why KLEE gave us so many test cases which are mostly incorrect.

### b. Analysis

As the picture I mentioned before. Function calling stack looks like the following figure.

<center><img src="../4/Call_stack_layout.svg.png" height="350"></center>

And there is no way to know the size of static array. As EFL binary files don't contain any information about how large the array is. Symbolic constraints solve engine cannot find an appropriate way to avoid engine visiting memory outside of the array. So, it may generate some test case can cause program encounter a **Segmentation Fault**.

When it comes to dynamic array which OS locates them in heap. Things don't get better. There is still no way to know its size. The only way we can reserve size information is define some structures or some high-level classes or compile sources into programs with debugging symbols. Such as vector supported by C++. But test tools can only support these standard structures or classes which tools know where they can reach size information. As for some user-defined structures or classes, testers must provide some extra information about where the size information is stored.

On the other hand, if we can analyze programs' source code directly, all information we need can be retrieved. But unfortunately, we don't know why, KLEE failed on this challenge. It generates a lot of out-of-bound visiting behaviors, which may lead to segmentation fault.

In order to solve this challenge, we can change binary files format to contain more information or our tool can using information contained in source code correctly, otherwise no tool can solve this challenge theoretically. The best thing as programmer can do is to have a good programming habit of always checking index before visiting elements of an array. And we can improve the test program to the following one:

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

➜  ConcTriton git:(master) ✗ programs/m.out 0
24244245
➜  ConcTriton git:(master) ✗ programs/m.out 0
13134895
➜  ConcTriton git:(master) ✗ programs/m.out 0
-217098
```



angr encountered some errors while stepping. Its IP was set to 0x0 after several steps. I've opened an issue on GitHub and I'm still waiting for official reply.

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

### b. Analysis

// TODO

## 3. Overflow

### a. Test program

```c
int main(int argc, char** argv) {
    // Maximum of signed int: 2147483647
    int a = 2147483640;
    int b = atoi(argv[1]);
    int c = 2;

    if (c * b < 0 && b > 0)
        return 2;
    else if (a + b < 0 && b > 0)
        return 1;
    else
        return 0;
}
```

angr output

```shell
➜  ConcTriton git:(master) ✗ python angr_run.py -r -s3 -C0 -l10 programs/overflow.c
WARNING | 2017-07-31 20:13:21,501 | claripy | Claripy is setting the recursion limit to 15000. If Python segfaults, I am sorry.



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
➜  ConcTriton git:(master) ✗ make triton P="o.out 1000000000"
echo "=== Using Triton ==="
=== Using Triton ===
/home/neil/Triton/build/triton triton_run.py programs/o.out 1000000000
Before start analysis
Before run program
[+] Take Snapshot
[+] In main
[+] In main() we set :
Input data      [0x7ffc771af737] = 49 1
Input data      [0x7ffc771af738] = 48 0
Input data      [0x7ffc771af739] = 48 0
Input data      [0x7ffc771af73a] = 48 0
Input data      [0x7ffc771af73b] = 48 0
Input data      [0x7ffc771af73c] = 48 0
Input data      [0x7ffc771af73d] = 48 0
Input data      [0x7ffc771af73e] = 48 0
Input data      [0x7ffc771af73f] = 48 0
Input data      [0x7ffc771af740] = 48 0
[+] Exit point
[[2453L, 4195696L, 4195709L], [2462L, 4195702L, 4195709L]]
Symbolic variables: {0L: SymVar_0:8, 1L: SymVar_1:8, 2L: SymVar_2:8, 3L: SymVar_3:8, 4L: SymVar_4:8, 5L: SymVar_5:8, 6L: SymVar_6:8, 7L: SymVar_7:8, 8L: SymVar_8:8, 9L: SymVar_9:8}
input.bound 0
model: {0L: <SolverModel object at 0x2ba2ea388468>, 1L: <SolverModel object at 0x2ba2ea388498>, 2L: <SolverModel object at 0x2ba2ea3884b0>, 3L: <SolverModel object at 0x2ba2ea3884c8>, 4L: <SolverModel object at 0x2ba2ea3884e0>, 5L: <SolverModel object at 0x2ba2ea3884f8>, 6L: <SolverModel object at 0x2ba2ea388510>, 7L: <SolverModel object at 0x2ba2ea388528>, 8L: <SolverModel object at 0x2ba2ea388540>, 9L: <SolverModel object at 0x2ba2ea388558>}
New input: {140722306742080L: 149L, 140722306742071L: 140L, 140722306742072L: 188L, 140722306742073L: 74L, 140722306742074L: 198L, 140722306742075L: 144L, 140722306742076L: 49L, 140722306742077L: 37L, 140722306742078L: 214L, 140722306742079L: 50L}
model: {0L: <SolverModel object at 0x2ba2ea388798>, 1L: <SolverModel object at 0x2ba2ea3887c8>, 2L: <SolverModel object at 0x2ba2ea3887e0>, 3L: <SolverModel object at 0x2ba2ea3887f8>, 4L: <SolverModel object at 0x2ba2ea388810>, 5L: <SolverModel object at 0x2ba2ea388828>, 6L: <SolverModel object at 0x2ba2ea388840>, 7L: <SolverModel object at 0x2ba2ea388858>, 8L: <SolverModel object at 0x2ba2ea388870>, 9L: <SolverModel object at 0x2ba2ea388888>}
New input: {140722306742080L: 64L, 140722306742071L: 48L, 140722306742072L: 81L, 140722306742073L: 84L, 140722306742074L: 128L, 140722306742075L: 66L, 140722306742076L: 132L, 140722306742077L: 191L, 140722306742078L: 64L, 140722306742079L: 154L}
[+] Restore snapshot
[+] In main
[+] In main() we set :
OD items:       [0x7ffc771af737] = 48 0
OD items:       [0x7ffc771af738] = 81 Q
OD items:       [0x7ffc771af739] = 84 T
OD items:       [0x7ffc771af73a] = 128
OD items:       [0x7ffc771af73b] = 66 B
OD items:       [0x7ffc771af73c] = 132
OD items:       [0x7ffc771af73d] = 191
OD items:       [0x7ffc771af73e] = 64 @
OD items:       [0x7ffc771af73f] = 154
OD items:       [0x7ffc771af740] = 64 @
[+] Exit point
[[1813L, 4195709L, 4195696L], [1833L, 4195734L, 4195721L]]
Symbolic variables: {0L: SymVar_0:8, 1L: SymVar_1:8, 2L: SymVar_2:8, 3L: SymVar_3:8, 4L: SymVar_4:8, 5L: SymVar_5:8, 6L: SymVar_6:8, 7L: SymVar_7:8, 8L: SymVar_8:8, 9L: SymVar_9:8}
input.bound 2
[+] Restore snapshot
[+] In main
[+] In main() we set :
OD items:       [0x7ffc771af737] = 140
OD items:       [0x7ffc771af738] = 188
OD items:       [0x7ffc771af739] = 74 J
OD items:       [0x7ffc771af73a] = 198
OD items:       [0x7ffc771af73b] = 144
OD items:       [0x7ffc771af73c] = 49 1
OD items:       [0x7ffc771af73d] = 37 %
OD items:       [0x7ffc771af73e] = 214
OD items:       [0x7ffc771af73f] = 50 2
OD items:       [0x7ffc771af740] = 149
[+] Exit point
[[1687L, 4195709L, 4195696L], [1707L, 4195734L, 4195721L]]
Symbolic variables: {0L: SymVar_0:8, 1L: SymVar_1:8, 2L: SymVar_2:8, 3L: SymVar_3:8, 4L: SymVar_4:8, 5L: SymVar_5:8, 6L: SymVar_6:8, 7L: SymVar_7:8, 8L: SymVar_8:8, 9L: SymVar_9:8}
input.bound 1
model: {}
[+] Done !
```

### b. Analysis



## 4. Float-point Number



## 5. Signed & Unsigned



## 6. File Reading



