import logging
import os
import ast
import sys

from triton import *
from pintool import *
from collections import OrderedDict


def logger_init(level=logging.INFO, log_format='[%(levelname)s] %(asctime)s - %(message)s'):
    logger = logging.getLogger('Global logger')
    logger.setLevel(level)

    ch = logging.StreamHandler()
    ch.setLevel(level)

    formatter = logging.Formatter(log_format)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


class ElfAddrs:
    def __init__(self, filename):
        self.binary = Elf(filename)
        self.syms = self.binary.getSymbolsTable()
        self.elfStart = 0
        self.elfEnd = 0

    def getSymAddr(self, symName, flag):
        for sym in self.syms:
            if sym.getName() == symName:
                addrSymStart = sym.getValue()
                if sym.getSize() > 0:
                    addrSymEnd = addrSymStart + sym.getSize() - 1
                else:
                    addrSymEnd = addrSymStart + sym.getSize()
                # print 'symbol %s_has been founded, addr: %x - %x' %(symName,
                # addrSymStart, addrSymEnd)
                break
        if flag:
            return addrSymEnd
        else:
            return addrSymStart

    def getSelfAddr(self):
        self.elfStart = self.getSymAddr('_init', 0)
        self.elfEnd = self.getSymAddr('_end', 0)
        return (self.elfStart, self.elfEnd)

    def isLocalInstr(self, addr):
        self.getSelfAddr()
        if addr <= self.elfEnd:
            return 1
        else:
            return 0


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


class CE:
    entryPoint = 0
    exitPoint = 0
    elfAddrs = None
    worklist = []
    inputTested = []
    whitelist = []
    stmList = []
    myPC = None
    program = None
    elfAddrs = None
    input = None
    AddrAfterEP = 0

    def __init__(self, inputSeed, elfAddrs, whitelist):
        CE.entryPoint = elfAddrs.getSymAddr('_start', 0)
        CE.exitPoint = elfAddrs.getSymAddr('main', 1)
        CE.elfAddrs = elfAddrs
        CE.worklist = [Input(inputSeed)]
        CE.whitelist = whitelist
        logger.info("entry: %x, exit: %x", CE.entryPoint, CE.exitPoint)

    @staticmethod
    def mainAnalysis(tID):
        logger.info("Find the main function")
        rdi = getCurrentRegisterValue(REG.RDI)  # argc
        rsi = getCurrentRegisterValue(REG.RSI)  # argv
        # print CPUSIZE.__dict__
        # argv0_addr = getCurrentMemoryValue(
        # getCurrentRegisterValue(REG.RSI), CPUSIZE.REG)  # argv[0] pointer
        # help(getCurrentMemoryValue)
        argv1_addr = getCurrentMemoryValue(rsi + 4, 4) # argv[1] pointer

        logger.info("In main() we set :")
        od = OrderedDict(sorted(CE.input.dataAddr.items()))

        for k, v in od.iteritems():
            logger.info("in main analysis 1")
            logger.info("\t[0x%x] = %x %c" % (k, v, v))
            print 'set memory'
            setCurrentMemoryValue(MemoryAccess(k, CPUSIZE.BYTE), v)
            convertMemoryToSymbolicVariable(
                MemoryAccess(k, CPUSIZE.BYTE), "addr_%d" % k)

        for idx, byte in enumerate(CE.input.data):
            logger.info("in main analysis two")
            if argv1_addr + idx not in CE.input.dataAddr:  # Not overwrite the previous setting
                logger.info("\t[0x%x] = %x %c" %
                            (argv1_addr + idx, ord(byte), ord(byte)))
                print MemoryAccess(argv1_addr + idx, CPUSIZE.BYTE)
                # setCurrentMemoryValue(MemoryAccess(
                    # argv1_addr + idx, CPUSIZE.BYTE), ord(byte))
                convertMemoryToSymbolicVariable(MemoryAccess(
                    argv1_addr + idx, CPUSIZE.BYTE), "addr_%d" % idx)

    @staticmethod
    def getGreedyExpr(inst):
        logger.info("Branching points: %d", len(CE.myPC))
        for j in range(CE.input.bound, len(CE.myPC)):
            logger.info("Inputbound: %d", j)
            expr = []
            for i in range(0, j):
                ripId = CE.myPC[i][0]
                addr = CE.myPC[i][1]
                symExp = getFullAst(
                    getSymbolicExpressionFromId(ripId).getAst())
                expr.append(ast.assert_(
                    ast.equal(symExp, ast.bv(addr,  CPUSIZE.QWORD_BIT))))
                #logger.debug("symexp: %s", symExp)

            ripId = CE.myPC[j][0]
            addr = CE.myPC[j][2]  # We choose the unexplored branch;
            symExp = getFullAst(getSymbolicExpressionFromId(ripId).getAst())
            expr.append(ast.assert_(
                ast.equal(symExp, ast.bv(addr,  CPUSIZE.QWORD_BIT))))

            expr = ast.compound(expr)
            # logger.debug("%s",expr)
            logger.info(
                "==================================================================================")
            model = getModel(expr)
            logger.info("Model: %d", len(model))

            if len(model) > 0:
                newInput = deepcopy(CE.input)
                newInput.setBound(j + 1)

                for k, v in model.items():
                    symVar = getSymbolicVariableFromId(k)
                    newInput.addDataAddress(
                        symVar.getKindValue(), v.getValue())

                isPresent = False

                for inp in CE.worklist:
                    if inp.dataAddr == newInput.dataAddr:
                        isPresent = True
                        break
                logger.info(
                    "The testcase is already in worklist" if isPresent else "New testcase has been detected")
                if not isPresent:
                    CE.worklist.append(newInput)

    @staticmethod
    def instrBefore(inst):
        # logger.info("Instruction before")
        # print(inst)
        if inst.getAddress() == CE.entryPoint:
            CE.AddrAfterEP = inst.getNextAddress()

        if inst.getAddress() == CE.AddrAfterEP:
            CE.myPC = []                     # Reset the path constraint
            CE.input = CE.worklist.pop()     # Take the first input
            # Add this input to the tested input
            CE.inputTested.append(CE.input)
            return

        if inst.getAddress() == CE.entryPoint:  # and not isSnapshotEnabled():
            # logger.info("Take Snapshot")
            # takeSnapshot()
            return

        if getRoutineName(inst.getAddress()) in CE.whitelist and inst.isBranch() and inst.getType() != OPCODE.JMP and inst.getOperands()[0].getType() == OPERAND.IMM:
            # if inst.isBranch() and inst.getType() != OPCODE.JMP and inst.getOperands()[0].getType() == OPERAND.IMM:
            # next address next from the current one
            addr1 = inst.getNextAddress()
            # Address in the instruction condition (branch taken)
            addr2 = inst.getOperands()[0].getValue()

            # Get the reference of the RIP symbolic register. RIP saves the
            # address of the next instructions to be executed.
            ripId = getSymbolicRegisterId(REG.RIP)
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

            if len(CE.worklist) > 0:  # and isSnapshotEnabled():
                logger.info("Restore snapshot")
                # restoreSnapshot()
            return
       # return

    @staticmethod
    def fini():
        logger.info("Done !")
        return

    @staticmethod
    def run():
        startAnalysisFromAddress(CE.entryPoint)
        print 'worklist', CE.worklist
        insertCall(CE.mainAnalysis,   INSERT_POINT.ROUTINE_ENTRY,
                   "main")  # Called when we are in main's beginning
        insertCall(CE.instrBefore,    INSERT_POINT.BEFORE)
        insertCall(CE.fini,           INSERT_POINT.FINI)
        runProgram()



def main():
    setArchitecture(ARCH.X86_64)
    print os.getcwd()
    elfAddrs = ElfAddrs("programs/c.out")
    logger.info("Set elf address")
    # Prepare for running
    taskCE = CE("2", elfAddrs, ["main"])
    logger.info("Set CE object")
    taskCE.run()


if __name__ == '__main__':
    logger = logger_init()
    main()
