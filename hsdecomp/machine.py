import capstone

from hsdecomp import ptrutil
from hsdecomp.types import *

def base_register(reg):
    base_reg_table = {
        capstone.x86.X86_REG_R8D: capstone.x86.X86_REG_R8,
        capstone.x86.X86_REG_R9D: capstone.x86.X86_REG_R9,
        capstone.x86.X86_REG_R10D: capstone.x86.X86_REG_R10,
        capstone.x86.X86_REG_R11D: capstone.x86.X86_REG_R11,
        capstone.x86.X86_REG_R12D: capstone.x86.X86_REG_R12,
        capstone.x86.X86_REG_R13D: capstone.x86.X86_REG_R13,
        capstone.x86.X86_REG_R14D: capstone.x86.X86_REG_R14,
        capstone.x86.X86_REG_R15D: capstone.x86.X86_REG_R15,
        capstone.x86.X86_REG_ESI: capstone.x86.X86_REG_RSI,
        capstone.x86.X86_REG_EDI: capstone.x86.X86_REG_RDI,
        capstone.x86.X86_REG_ESP: capstone.x86.X86_REG_RSP,
        capstone.x86.X86_REG_EBP: capstone.x86.X86_REG_RBP,
        capstone.x86.X86_REG_EAX: capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_EBX: capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_ECX: capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_EDX: capstone.x86.X86_REG_RDX,
    }
    if reg in base_reg_table:
        return base_reg_table[reg]
    else:
        return reg

class Machine:
    def __init__(self, settings, heaps, stack, registers):
        self.settings = settings
        self.heaps = heaps
        self.stack = stack
        self.registers = registers
        self.heap = []

    def simulate(self, instructions):
        for insn in instructions:
            if insn.mnemonic == 'add':
                assert insn.operands[1].type == capstone.x86.X86_OP_IMM
                self.store(insn.operands[0], ptrutil.pointer_offset(self.settings, self.load(insn.operands[0]), insn.operands[1].imm))
                if insn.operands[0].type == capstone.x86.X86_OP_REG and base_register(insn.operands[0].reg) == self.settings.rt.heap_register:
                    self.heap += [None] * (insn.operands[1].imm // self.settings.rt.word.size)
            elif insn.mnemonic == 'mov':
                self.store(insn.operands[0], self.load(insn.operands[1]))
            elif insn.mnemonic == 'lea':
                self.store(insn.operands[0], self.read_memory_operand(insn.operands[1].mem))

    def read_memory_operand(self, operand):
        if base_register(operand.base) in self.registers:
            assert operand.index == capstone.x86.X86_REG_INVALID
            return ptrutil.pointer_offset(self.settings, self.registers[base_register(operand.base)], operand.disp)
        else:
            return UnknownValue()

    def load(self, operand):
        if operand.type == capstone.x86.X86_OP_REG:
            if base_register(operand.reg) in self.registers:
                return self.registers[base_register(operand.reg)]
            else:
                return UnknownValue()
        elif operand.type == capstone.x86.X86_OP_MEM:
            pointer = self.read_memory_operand(operand.mem)
            if isinstance(pointer, UnknownValue):
                return UnknownValue()
            elif isinstance(pointer, Tagged):
                if pointer.tag == 0:
                    return ptrutil.dereference(self.settings, pointer.untagged, self.heaps, self.stack)
                else:
                    return UnknownValue()
        elif operand.type == capstone.x86.X86_OP_IMM:
            return ptrutil.make_tagged(self.settings, StaticValue(value = operand.imm))
        else:
            assert False, "unknown type of operand in Machine.load"

    def store(self, operand, value):
        if operand.type == capstone.x86.X86_OP_MEM:
            output = self.read_memory_operand(operand.mem)
            if isinstance(output, Tagged):
                assert output.tag == 0
                assert isinstance(output.untagged, Offset)
                if isinstance(output.untagged.base, HeapPointer):
                    self.heap[output.untagged.index] = value
                elif isinstance(output.untagged.base, StackPointer):
                    adjusted_index = output.untagged.index + len(self.stack)
                    if adjusted_index < 0:
                        self.stack = [None] * (-adjusted_index) + self.stack
                        self.stack[0] = value
                    else:
                        self.stack[adjusted_index] = value
        elif operand.type == capstone.x86.X86_OP_REG:
            self.registers[base_register(operand.reg)] = value
