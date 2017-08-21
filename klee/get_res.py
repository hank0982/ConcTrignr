import sys
import os


nums = int(sys.argv[1])

for i in range(nums):
    cmd = 'ktest-tool --write-ints klee-last/test%06d.ktest' % (i + 1)
    print(cmd)
    os.system(cmd)
