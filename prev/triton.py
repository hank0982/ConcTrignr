import ast
import os 
import sys

from    triton      import *
from    pintool     import *
from    collections import OrderedDict
from    copy        import deepcopy

sys.path.append(os.getcwd())
from	addrutils	import *
from	ce_script	import *
from	logger		import *

if __name__=='__main__':
    # Set architecture
    logger.info('Start triton...')
    setArchitecture(ARCH.X86_64)
    filename = getElfName()
    logger.info('Processing file:%s' %filename)
    elfAddrs = ElfAddrs(filename)
    taskCE = CE("1", elfAddrs, ["main"])      
    taskCE.run()      
