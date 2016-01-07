import capstone

import ptrutil
from hstypes import *

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

def read_memory_operand(parsed, operand, registers):
    if base_register(operand.base) in registers:
        assert operand.index == capstone.x86.X86_REG_INVALID
        return ptrutil.pointer_offset(parsed, registers[base_register(operand.base)], operand.disp)
    else:
        return UnknownValue()

def read_insn(parsed, insn, registers, stack):
    operand = insn.operands[1]

    if operand.type == capstone.x86.X86_OP_REG:
        assert insn.mnemonic == 'mov'
        if base_register(operand.reg) in registers:
            return registers[base_register(operand.reg)]
        else:
            return UnknownValue()
    elif operand.type == capstone.x86.X86_OP_MEM:
        pointer = read_memory_operand(parsed, operand.mem, registers)
        if insn.mnemonic == 'mov':
            return ptrutil.dereference(parsed, pointer, stack)
        elif insn.mnemonic == 'lea':
            return pointer
        else:
            assert False, "unknown instruction in read_insn"
    elif operand.type == capstone.x86.X86_OP_IMM:
        assert insn.mnemonic == 'mov'
        return StaticValue(value = operand.imm)
    else:
        assert False, "unknown type of operand in read_insn"

class Machine:
    def __init__(self, stack, registers):
        self.stack = stack
        self.registers = registers
        self.heap = []

    def simulate(self, parsed, instructions):
        for insn in instructions:
            if insn.mnemonic == 'add':
                if insn.operands[0].type == capstone.x86.X86_OP_REG:
                    reg = base_register(insn.operands[0].reg)
                    if reg in self.registers:
                        assert insn.operands[1].type == capstone.x86.X86_OP_IMM
                        self.registers[reg] = ptrutil.pointer_offset(parsed, self.registers[reg], insn.operands[1].imm)
                        if reg == parsed['heap-register']:
                            self.heap += [None] * (insn.operands[1].imm // parsed['word-size'])
            elif insn.mnemonic == 'mov' or insn.mnemonic == 'lea':
                if insn.operands[0].type == capstone.x86.X86_OP_MEM:
                    output = read_memory_operand(parsed, insn.operands[0].mem, self.registers)
                    if isinstance(output, HeapPointer):
                        assert output.tag == 0
                        self.heap[output.index] = read_insn(parsed, insn, self.registers, self.stack)
                    elif isinstance(output, StackPointer):
                        self.stack[output.index] = read_insn(parsed, insn, self.registers, self.stack)
                elif insn.operands[0].type == capstone.x86.X86_OP_REG:
                    self.registers[base_register(insn.operands[0].reg)] = read_insn(parsed, insn, self.registers, self.stack)
