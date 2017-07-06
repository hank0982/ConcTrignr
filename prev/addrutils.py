import ast
import sys
from triton import *


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
