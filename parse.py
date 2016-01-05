import sys
import struct
import capstone

import show
from hstypes import *

def disasm_from_raw(parsed, address, num_insns):
    return parsed['capstone'].disasm(parsed['binary'][parsed['text-offset'] + address:], address, num_insns)

def disasm_from(parsed, address):
    instructions = []
    incomplete = True
    while incomplete:
        for insn in disasm_from_raw(parsed, address, 20):
            address += insn.size
            instructions.append(insn)
            if insn.mnemonic == 'jmp':
                incomplete = False
                break
    return instructions

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

def read_stack_adjustment(parsed, instructions):
    for insn in instructions:
        if insn.mnemonic == 'add' and base_register(insn.operands[0].reg) == parsed['stack-register']:
            assert insn.operands[1].type == capstone.x86.X86_OP_IMM
            return -insn.operands[1].imm
    return 0

def read_heap_check(instructions):
    for index in range(len(instructions) - 2):
        if instructions[index].mnemonic == 'add' and instructions[index + 1].mnemonic == 'cmp' and instructions[index + 2].mnemonic == 'ja':
            return instructions[index].operands[1].imm
    return 0

def read_half_word(parsed, file_offset):
    return struct.unpack(parsed['halfword-struct'], parsed['binary'][file_offset:file_offset+parsed['halfword-size']])[0]

def read_word(parsed, file_offset):
    return struct.unpack(parsed['word-struct'], parsed['binary'][file_offset:file_offset+parsed['word-size']])[0]

def retag(parsed, pointer, tag):
    if isinstance(pointer, HeapPointer):
        return pointer._replace(tag = tag)
    elif isinstance(pointer, StaticValue):
        tagmask = parsed['word-size'] - 1
        cleared = pointer.value & ~tagmask
        return StaticValue(value = cleared | tag)
    else:
        assert False,"bad pointer to retag"

def pointer_offset(parsed, pointer, offset):
    if isinstance(pointer, HeapPointer):
        offset += pointer.tag
        return HeapPointer(heap_segment = pointer.heap_segment, index = pointer.index + offset // parsed['word-size'], tag = offset % parsed['word-size'])
    elif isinstance(pointer, StaticValue):
        return StaticValue(value = pointer.value + offset)
    elif isinstance(pointer, StackPointer):
        return StackPointer(index = pointer.index + offset // parsed['word-size'])
    else:
        assert False,"bad pointer to offset"

def read_memory_operand(parsed, operand, registers):
    if base_register(operand.base) in registers:
        assert operand.index == capstone.x86.X86_REG_INVALID
        return pointer_offset(parsed, registers[base_register(operand.base)], operand.disp)
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
            return dereference(parsed, pointer, stack)
        elif insn.mnemonic == 'lea':
            return pointer
        else:
            assert False, "unknown instruction in read_insn"
    elif operand.type == capstone.x86.X86_OP_IMM:
        assert insn.mnemonic == 'mov'
        return StaticValue(value = operand.imm)
    else:
        assert False, "unknown type of operand in read_insn"

def read_num_args(parsed, address):
    return read_half_word(parsed, parsed['text-offset'] + address - parsed['halfword-size']*5)

def read_closure_type(parsed, address):
    type_table = {
        1: 'constructor',
        2: 'constructor (1 ptr, 0 nonptr)',
        3: 'constructor (0 ptr, 1 nonptr)',
        4: 'constructor (2 ptr, 0 nonptr)',
        5: 'constructor (1 ptr, 1 nonptr)',
        6: 'constructor (0 ptr, 2 nonptr)',
        7: 'constructor (static)',
        8: 'constructor (no CAF, static)',
        9: 'function',
        10: 'function (1 ptr, 0 nonptr)',
        11: 'function (0 ptr, 1 nonptr)',
        12: 'function (2 ptr, 0 nonptr)',
        13: 'function (1 ptr, 1 nonptr)',
        14: 'function (0 ptr, 2 nonptr)',
        15: 'function (static)',
        16: 'thunk',
        17: 'thunk (1 ptr, 0 nonptr)',
        18: 'thunk (0 ptr, 1 nonptr)',
        19: 'thunk (2 ptr, 0 nonptr)',
        20: 'thunk (1 ptr, 1 nonptr)',
        21: 'thunk (0 ptr, 2 nonptr)',
        22: 'thunk (static)',
        23: 'selector'
    }
    type = read_half_word(parsed, parsed['text-offset'] + address - parsed['halfword-size']*2)
    if type in type_table:
        return type_table[type]
    else:
        return 'unknown: ' + str(type)

def dereference(parsed, pointer, stack):
    if isinstance(pointer, StaticValue):
        assert pointer.value % parsed['word-size'] == 0
        return StaticValue(value = read_word(parsed, parsed['data-offset'] + pointer.value))
    elif isinstance(pointer, HeapPointer):
        assert pointer.tag == 0
        return parsed['heaps'][pointer.heap_segment][pointer.index]
    elif isinstance(pointer, StackPointer):
        return stack[pointer.index]
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False, "bad pointer dereference"

def read_closure(parsed, pointer):
    try:
        if isinstance(pointer, Argument) or isinstance(pointer, CaseArgument):
            return

        if parsed['opts'].verbose:
            print("Found closure:")
            print("    Pointer:", show.show_pretty(parsed, pointer))

        if isinstance(pointer, StaticValue) and show.name_is_library(show.get_name_for_address(parsed, pointer.value)):
            if parsed['opts'].verbose:
                print("    Library defined!")
                print()
            return

        untagged_pointer = retag(parsed, pointer, 0)

        info_pointer = dereference(parsed, untagged_pointer, [])
        assert isinstance(info_pointer, StaticValue)

        info_type = read_closure_type(parsed, info_pointer.value)
        if info_type[:11] == 'constructor':
            num_ptrs = read_half_word(parsed, parsed['text-offset'] + info_pointer.value - parsed['halfword-size']*4)
            num_non_ptrs = read_half_word(parsed, parsed['text-offset'] + info_pointer.value - parsed['halfword-size']*3)

            args = []
            arg_pointer = untagged_pointer
            for i in range(num_ptrs + num_non_ptrs):
                arg_pointer = pointer_offset(parsed, arg_pointer, parsed['word-size']);
                args.append(dereference(parsed, arg_pointer, []))

            parsed['interpretations'][pointer] = Apply(func = info_pointer, func_type = 'constructor', args = args, pattern = 'p' * num_ptrs + 'n' * num_non_ptrs)
            if parsed['opts'].verbose:
                print()

            for arg in args[:num_ptrs]:
                read_closure(parsed, arg)

            return
        elif info_type[:8] == 'function':
            num_args = read_num_args(parsed, info_pointer.value)
        else:
            num_args = 0

        if parsed['opts'].verbose:
            print()

        parsed['interpretations'][pointer] = info_pointer

        read_function_thunk(parsed, info_pointer, retag(parsed, pointer, num_args), num_args)
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error when processing closure at", show.show_pretty(parsed, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    No Disassembly Available")
        print()

def read_case(parsed, pointer, stack, scrutinee):
    try:
        if parsed['opts'].verbose:
            print("Found case inspection!")

        info_name = show.get_name_for_address(parsed, pointer.value)
        if parsed['opts'].verbose:
            print("    Name:", show.demangle(info_name))

        first_instructions = list(disasm_from_raw(parsed, pointer.value, 4))
        if len(first_instructions) == 4 and first_instructions[0].mnemonic == 'mov' and first_instructions[1].mnemonic == 'and' and first_instructions[2].mnemonic == 'cmp' and first_instructions[3].mnemonic == 'jae':
            false_address = sum(map(lambda insn: insn.size, first_instructions)) + pointer.value
            true_address = first_instructions[3].operands[0].imm

            false_pointer = StaticValue(value = false_address)
            true_pointer = StaticValue(value = true_address)

            parsed['interpretations'][pointer] = CaseBool(scrutinee = scrutinee, arm_true = true_pointer, arm_false = false_pointer)

            if parsed['opts'].verbose:
                print()
                print("Found case arm:")
                print("    From case:", info_name)
                print("    Pattern: True")
            read_code(parsed, true_pointer, stack, {parsed['main-register']: CaseArgument(inspection = pointer)})

            if parsed['opts'].verbose:
                print("Found case arm:")
                print("    From case:", info_name)
                print("    Pattern: False")
            read_code(parsed, false_pointer, stack, {parsed['main-register']: CaseArgument(inspection = pointer)})
        else:
            read_code(parsed, pointer, stack, {parsed['main-register']: CaseArgument(inspection = pointer)})
            parsed['interpretations'][pointer] = CaseDefault(scrutinee = scrutinee, bound_ptr = pointer, arm = parsed['interpretations'][pointer])
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing case at", show.show_pretty(parsed, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm_from(parsed, pointer.value):
            print("        " + show.show_instruction(insn))
        print()

def read_function_thunk(parsed, pointer, main_register, num_args):
    if parsed['opts'].verbose:
        print("Found function/thunk!")

    assert isinstance(pointer, StaticValue)

    info_name = show.get_name_for_address(parsed, pointer.value)
    if parsed['opts'].verbose:
        print("    Name:", show.demangle(info_name))
        print("    Arity:", num_args)

    if show.name_is_library(info_name):
        if parsed['opts'].verbose:
            print("    Library Defined!")
            print()
        return

    extra_stack = []
    registers = {}
    registers[parsed['main-register']] = main_register
    for i in range(num_args):
        if i < len(parsed['arg-registers']):
            registers[parsed['arg-registers'][i]] = Argument(index = i, func = info_name)
        else:
            extra_stack.append(Argument(index = i, func = info_name))

    if num_args > 0:
        parsed['num-args'][pointer] = num_args

    read_code(parsed, pointer, extra_stack, registers)

def read_code(parsed, pointer, extra_stack, registers):
    try:
        assert isinstance(pointer, StaticValue)

        if pointer in parsed['interpretations']:
            if parsed['opts'].verbose:
                print("    Seen before!")
                print()
            return

        instructions = disasm_from(parsed, pointer.value)

        stack_size = read_stack_adjustment(parsed, instructions) // parsed['word-size']
        if parsed['opts'].verbose:
            print("    Stack space:", stack_size)

        if stack_size < 0:
            stack_clip = -stack_size
            stack_size = 0
        else:
            stack_clip = 0

        heap_size = read_heap_check(instructions) // parsed['word-size']
        if parsed['opts'].verbose:
            print("    Heap space:", heap_size)

        heap = [None] * heap_size
        stack = [None] * stack_size + extra_stack

        registers[parsed['heap-register']] = HeapPointer(heap_segment = pointer, index = heap_size - 1, tag = 0)
        registers[parsed['stack-register']] = StackPointer(index = stack_size)
        for insn in instructions:
            if insn.mnemonic == 'mov' or insn.mnemonic == 'lea':
                if insn.operands[0].type == capstone.x86.X86_OP_MEM:
                    if base_register(insn.operands[0].mem.base) == parsed['heap-register']:
                        heap_loc = heap_size - 1 + insn.operands[0].mem.disp // parsed['word-size']
                        heap[heap_loc] = read_insn(parsed, insn, registers, stack)
                    elif base_register(insn.operands[0].mem.base) == parsed['stack-register']:
                        stack_loc = stack_size + insn.operands[0].mem.disp // parsed['word-size']
                        stack[stack_loc] = read_insn(parsed, insn, registers, stack)
                elif insn.operands[0].type == capstone.x86.X86_OP_REG:
                    registers[base_register(insn.operands[0].reg)] = read_insn(parsed, insn, registers, stack)

        stack = stack[stack_clip:]

        parsed['heaps'][pointer] = heap
        if parsed['opts'].verbose:
            print("    Heap:", list(map(lambda h: show.show_pretty(parsed, h), heap)))
            print("    Stack:", list(map(lambda s: show.show_pretty(parsed, s), stack)))

        if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM and base_register(instructions[-1].operands[0].mem.base) == parsed['stack-register']:
            if parsed['opts'].verbose:
                print("    Interpretation: return", show.show_pretty(parsed, registers[parsed['main-register']]))
                print()

            parsed['interpretations'][pointer] = registers[parsed['main-register']]

            read_closure(parsed, registers[parsed['main-register']])
        else:
            worklist = []
            uses = []

            if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM:
                assert base_register(instructions[-1].operands[0].mem.base) == parsed['main-register']
                assert instructions[-1].operands[0].mem.disp == 0

                if parsed['opts'].verbose:
                    print("    Interpretation: evaluate", show.show_pretty(parsed, registers[parsed['main-register']]))

                stack_index = 0
                interpretation = registers[parsed['main-register']]
                worklist.append({'type': 'closure', 'pointer': registers[parsed['main-register']]})
            elif instructions[-1].operands[0].type == capstone.x86.X86_OP_IMM:
                jmp_address = instructions[-1].operands[0].imm
                if jmp_address in parsed['address-to-name'] and parsed['address-to-name'][jmp_address][:7] == 'stg_ap_':
                    func = parsed['address-to-name'][jmp_address]
                    if func.split('_')[2] == '0':
                        num_args = 0
                        arg_pattern = ''
                    else:
                        num_args = len(func.split('_')[2])
                        arg_pattern = func.split('_')[2]
                    called = registers[parsed['main-register']]
                    worklist.append({'type': 'closure', 'pointer': called})
                    func_type = 'closure'
                else:
                    num_args = read_num_args(parsed, jmp_address)
                    arg_pattern = 'p' * num_args
                    called = StaticValue(value = jmp_address)
                    worklist.append({'type': 'function/thunk', 'pointer': called, 'main-register': registers[parsed['main-register']], 'num-args': num_args})
                    func_type = 'info'

                if parsed['opts'].verbose:
                    print("    Number of args:", num_args)

                args = []
                stack_index = num_args
                for reg, i in zip(parsed['arg-registers'], range(num_args)):
                    args.append(registers[reg])
                    stack_index -= 1
                args += stack[:stack_index]

                if parsed['opts'].verbose:
                    print("    Interpretation: call", show.show_pretty(parsed, called), "on", list(map(lambda s: show.show_pretty(parsed, s), args)))
                interpretation = Apply(func_type = func_type, func = called, args = args, pattern = arg_pattern)

                for arg, pat in zip(args, arg_pattern):
                    if pat == 'p':
                        worklist.append({'type': 'closure', 'pointer': arg})

            while stack_index < len(stack):
                assert isinstance(stack[stack_index], StaticValue)
                cont_name = show.get_name_for_address(parsed, stack[stack_index].value)
                if cont_name[:7] == 'stg_ap_':
                    assert cont_name[-5:] == '_info'
                    arg_pattern = cont_name.split('_')[2]
                    num_extra_args = len(arg_pattern)
                    if parsed['opts'].verbose:
                        print("                    then apply the result to", list(map(lambda s: show.show_pretty(parsed, s), stack[stack_index+1:][:num_extra_args])))
                    interpretation = Apply(func_type = 'closure', func = interpretation, args = stack[stack_index+1:][:num_extra_args], pattern = arg_pattern)
                    for arg in stack[stack_index+1:][:num_extra_args]:
                        worklist.append({'type': 'closure', 'pointer': arg})
                    stack_index += 1 + num_extra_args
                elif cont_name == 'stg_upd_frame_info' or cont_name == 'stg_bh_upd_frame_info':
                    if parsed['opts'].verbose:
                        print("                    then update the thunk at", show.show_pretty(parsed, stack[stack_index + 1]))
                    stack_index += 2
                else:
                    if parsed['opts'].verbose:
                        print("                    then inspect using", show.show_pretty(parsed, stack[stack_index]))
                    worklist.append({'type': 'case', 'pointer': stack[stack_index], 'stack': stack[stack_index:], 'scrutinee': interpretation})
                    interpretation = stack[stack_index]
                    stack_index = len(stack)
            if parsed['opts'].verbose:
                print()

            parsed['interpretations'][pointer] = interpretation

            for work in worklist:
                if work['type'] == 'closure':
                    read_closure(parsed, work['pointer'])
                elif work['type'] == 'function/thunk':
                    read_function_thunk(parsed, work['pointer'], work['main-register'], work['num-args'])
                elif work['type'] == 'case':
                    read_case(parsed, work['pointer'], work['stack'], work['scrutinee'])
                else:
                    assert False,"bad work in worklist"
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing code at", show.show_pretty(parsed, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm_from(parsed, pointer.value):
            print("        " + show.show_instruction(insn))
        print()
