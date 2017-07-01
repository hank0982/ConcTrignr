import ast
import os 
import sys
import chkpoint

from    triton      import *
from    pintool     import *
from    collections import OrderedDict
from    copy        import deepcopy

sys.path.append(os.getcwd())
from	addrutils	import *
from	logger		import *


class Input(object):

    def __init__(self, data):
        self.__data = data
        self.__bound = 0
        self.__dataAddr = dict()

    @property
    def data(self):
        return self.__data

    @property
    def bound(self):
        return self.__bound

    @property
    def dataAddr(self):
        return self.__dataAddr

    def setBound(self, bound):
        self.__bound = bound

    def addDataAddress(self, address, value):
        self.__dataAddr[address] = value

class CE(object):

    entryPoint	= 0
    exitPoint	= 0
    elfAddrs	= None 
    worklist   	= []
    inputTested	= []
    whitelist  	= []
    stmList  	= []
    myPC	= None
    program    	= None
    elfAddrs 	= None
    input      	= None
    AddrAfterEP= 0
    chk1 = chkpoint.newSnapshot()
    
    def __init__(self,inputSeed,elfAddrs,whitelist):
        CE.entryPoint	= elfAddrs.getSymAddr('_start',0)
        CE.exitPoint  	= elfAddrs.getSymAddr('main',1)
        CE.elfAddrs	= elfAddrs
        CE.worklist 	= [Input(inputSeed)]
        CE.whitelist  	= whitelist
	logger.info("entry: %x, exit: %x", CE.entryPoint, CE.exitPoint)

    @staticmethod
    def getGreedyExpr(inst):
	logger.debug ("Branching points: %d", len(CE.myPC))
        for j in range(CE.input.bound, len(CE.myPC)):
	    logger.debug("Inputbound: %d", j)
            expr = []
            for i in range(0,j):
                ripId = CE.myPC[i][0]
                addr = CE.myPC[i][1]
                symExp = getFullAst(getSymbolicExpressionFromId(ripId).getAst())
                expr.append(ast.assert_(ast.equal(symExp, ast.bv(addr,  CPUSIZE.QWORD_BIT))))
	        #logger.debug("symexp: %s", symExp)

            ripId = CE.myPC[j][0]
            addr = CE.myPC[j][2] # We choose the unexplored branch;
            symExp = getFullAst(getSymbolicExpressionFromId(ripId).getAst())
            expr.append(ast.assert_(ast.equal(symExp, ast.bv(addr,  CPUSIZE.QWORD_BIT))))

            expr = ast.compound(expr)
	    #logger.debug("%s",expr)
	    logger.debug("==================================================================================")
            model = getModel(expr)
            logger.debug("Model: %d", len(model))

            if len(model) > 0:
                newInput = deepcopy(CE.input)
                newInput.setBound(j + 1)

                for k,v in model.items():
                    symVar = getSymbolicVariableFromId(k)
                    newInput.addDataAddress(symVar.getKindValue(), v.getValue())

                isPresent = False

                for inp in CE.worklist:
                    if inp.dataAddr == newInput.dataAddr:
                        isPresent = True
                        break
		logger.info("The testcase is already in worklist" if isPresent else "New testcase has been detected")
                if not isPresent:
                    CE.worklist.append(newInput)

    @staticmethod
    def instrBefore(inst):

        if inst.getAddress() == CE.entryPoint:
            CE.AddrAfterEP = inst.getNextAddress()

        if inst.getAddress() == CE.AddrAfterEP:
            CE.myPC = []                                  # Reset the path constraint
            CE.input = CE.worklist.pop()     # Take the first input
            CE.inputTested.append(CE.input)  # Add this input to the tested input
            return

        if inst.getAddress() == CE.entryPoint: #and not isSnapshotEnabled():
            logger.info("Take Snapshot")
            CE.chk1.setChkpoint()
            #takeSnapshot()
            return

        #logger.info("Instruction:%x", inst.getAddress());
	# A blacklist mechanism
        #for expr in inst.getSymbolicExpressions(): 
        #    logger.info(expr) 
        #    logger.info(expr.getIsBlackListed());
	#    return
 	#The ref!ID is assigned in symbolicExpression.cpp
	#The print format is specified in astSmtRepresentation.cpp

        if getRoutineName(inst.getAddress()) in CE.whitelist and inst.isBranch() and inst.getType() != OPCODE.JMP and inst.getOperands()[0].getType() == OPERAND.IMM:
        #if inst.isBranch() and inst.getType() != OPCODE.JMP and inst.getOperands()[0].getType() == OPERAND.IMM:
            addr1 = inst.getNextAddress()              # next address next from the current one
            addr2 = inst.getOperands()[0].getValue()   # Address in the instruction condition (branch taken)

            ripId = getSymbolicRegisterId(REG.RIP)            # Get the reference of the RIP symbolic register. RIP saves the address of the next instructions to be executed.
            #logger.debug("RIP_ID: %d", ripId)

            # [PC id, address taken, address not taken]
            if inst.isConditionTaken():
                CE.myPC.append([ripId, addr2, addr1])
            else:
                CE.myPC.append([ripId, addr1, addr2])

            return

        if inst.getAddress() == CE.exitPoint:
            logger.info("Exit point")

            CE.getGreedyExpr(inst)
            CE.stmList = []
	    
            if len(CE.worklist) > 0: #and isSnapshotEnabled():
                logger.info("Restore snapshot")
                #restoreSnapshot()
                CE.chk1.restoreChkpoint()
            return
       #return


    @staticmethod
    def fini():
        logger.info("Done !")
        return


    @staticmethod
    def mainAnalysis(tID):
        logger.info("Find the main function")
        rdi = getCurrentRegisterValue(REG.RDI) # argc
        rsi = getCurrentRegisterValue(REG.RSI) # argv
        argv0_addr = getCurrentMemoryValue(getCurrentRegisterValue(REG.RSI), CPUSIZE.REG) # argv[0] pointer
        argv1_addr = getCurrentMemoryValue(rsi + CPUSIZE.REG, CPUSIZE.REG)                # argv[1] pointer

        logger.info("In main() we set :")
        od = OrderedDict(sorted(CE.input.dataAddr.items()))

        for k,v in od.iteritems():
            logger.info("\t[0x%x] = %x %c" % (k, v, v))
            setCurrentMemoryValue(MemoryAccess(k, CPUSIZE.BYTE), v)
            convertMemoryToSymbolicVariable(MemoryAccess(k, CPUSIZE.BYTE), "addr_%d" % k)

        for idx, byte in enumerate(CE.input.data):
            if argv1_addr + idx not in CE.input.dataAddr: # Not overwrite the previous setting
                logger.info("\t[0x%x] = %x %c" % (argv1_addr + idx, ord(byte), ord(byte)))
                setCurrentMemoryValue(MemoryAccess(argv1_addr + idx, CPUSIZE.BYTE), ord(byte))
                convertMemoryToSymbolicVariable(MemoryAccess(argv1_addr + idx, CPUSIZE.BYTE), "addr_%d" % idx)


    @staticmethod
    def run():
        startAnalysisFromAddress(CE.entryPoint)
        insertCall(CE.mainAnalysis,   INSERT_POINT.ROUTINE_ENTRY, "main") # Called when we are in main's beginning
        insertCall(CE.instrBefore,    INSERT_POINT.BEFORE)
        insertCall(CE.fini,           INSERT_POINT.FINI)
        runProgram()
