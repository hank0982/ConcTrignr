from triton import *
from pintool import *


if __name__ == '__main__':
    setArchitecture(ARCH.X86_64)
    startAnalysisFromSymbol('check')
    # Run the instrumentation - Never returns
    runProgram()
