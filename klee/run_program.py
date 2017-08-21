import sys
import os
from termcolor import colored
from subprocess import Popen, call, PIPE


nums = int(sys.argv[1])

lib_path = '/home/klee/klee_build/klee/lib/'

print(colored('[+] Compiling...', 'green'))

os.system('sh run_program.sh')
os.system('gcc -L ' + lib_path + ' ' + sys.argv[2] + ' -lkleeRuntest')

print(colored('[+] Compilied', 'green'))

running_res = set()
for i in range(nums):
    cmd = 'KTEST_FILE=klee-last/test%06d.ktest' % (i + 1)
    os.system(cmd + ' ./a.out')
    pipe = Popen(['echo', '$?'], stdout=PIPE)
    res = pipe.wait()
    running_res.add(res)

print(colored('Return values set: ' + repr(running_res), 'cyan'))
print(colored('Total: ' + str(len(running_res)), 'cyan'))
