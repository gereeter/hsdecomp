import sys
import struct
import copy
import capstone

import ptrutil
import machine
import show
from hstypes import *

def disasm_from_raw(settings, address, num_insns):
    return settings.capstone.disasm(settings.binary[settings.text_offset + address:], address, num_insns)

def disasm_from(settings, address):
    return disasm_from_until(settings, address, lambda insn: insn.mnemonic == 'jmp')

def disasm_from_until(settings, address, predicate):
    instructions = []
    incomplete = True
    while incomplete:
        for insn in disasm_from_raw(settings, address, 20):
            address += insn.size
            instructions.append(insn)
            if predicate(insn):
                incomplete = False
                break
    return instructions

def retag(settings, pointer, tag):
    if isinstance(pointer, HeapPointer):
        return pointer._replace(tag = tag)
    elif isinstance(pointer, StaticValue):
        tagmask = settings.rt.word.size - 1
        cleared = pointer.value & ~tagmask
        return StaticValue(value = cleared | tag)
    else:
        assert False,"bad pointer to retag"

def read_num_args(settings, address):
    return ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*5)

def read_closure_type(settings, address):
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
    type = ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*2)
    if type in type_table:
        return type_table[type]
    else:
        return 'unknown: ' + str(type)

def read_closure(settings, parsed, pointer):
    try:
        if isinstance(pointer, Argument) or isinstance(pointer, CaseArgument):
            return

        if settings.opts.verbose:
            print("Found closure:")
            print("    Pointer:", show.show_pretty(settings, pointer))

        if isinstance(pointer, StaticValue) and show.name_is_library(show.get_name_for_address(settings, pointer.value)):
            if settings.opts.verbose:
                print("    Library defined!")
                print()
            return

        untagged_pointer = retag(settings, pointer, 0)

        info_pointer = ptrutil.dereference(settings, parsed, untagged_pointer, [])
        assert isinstance(info_pointer, StaticValue)

        info_type = read_closure_type(settings, info_pointer.value)
        if info_type[:11] == 'constructor':
            num_ptrs = ptrutil.read_half_word(settings, settings.text_offset + info_pointer.value - settings.rt.halfword.size*4)
            num_non_ptrs = ptrutil.read_half_word(settings, settings.text_offset + info_pointer.value - settings.rt.halfword.size*3)

            args = []
            arg_pointer = untagged_pointer
            for i in range(num_ptrs + num_non_ptrs):
                arg_pointer = ptrutil.pointer_offset(settings, arg_pointer, settings.rt.word.size);
                args.append(ptrutil.dereference(settings, parsed, arg_pointer, []))

            parsed['interpretations'][pointer] = Apply(func = Pointer(info_pointer), func_type = 'constructor', args = list(map(Pointer, args)), pattern = 'p' * num_ptrs + 'n' * num_non_ptrs)
            if settings.opts.verbose:
                print()

            for arg in args[:num_ptrs]:
                read_closure(settings, parsed, arg)

            return
        elif info_type[:8] == 'function':
            num_args = read_num_args(settings, info_pointer.value)
        else:
            num_args = 0

        if settings.opts.verbose:
            print()

        parsed['interpretations'][pointer] = Pointer(info_pointer)

        read_function_thunk(settings, parsed, info_pointer, retag(settings, pointer, num_args), num_args)
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error when processing closure at", show.show_pretty(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    No Disassembly Available")
        print()

def read_case(settings, parsed, pointer, stack, scrutinee):
    try:
        if settings.opts.verbose:
            print("Found case inspection!")

        info_name = show.get_name_for_address(settings, pointer.value)
        if settings.opts.verbose:
            print("    Name:", show.demangle(info_name))

        mach = machine.Machine(settings, parsed, copy.deepcopy(stack), {
            settings.rt.main_register: CaseArgument(inspection = pointer),
            settings.rt.stack_register: StackPointer(index = -len(stack))
        })
        first_instructions = disasm_from_until(settings, pointer.value, lambda insn: insn.group(capstone.x86.X86_GRP_JUMP))
        mach.simulate(first_instructions)

        if first_instructions[-2].mnemonic == 'cmp' and first_instructions[-2].operands[0].type == capstone.x86.X86_OP_REG and machine.base_register(first_instructions[-2].operands[0].reg) in mach.registers and isinstance(mach.registers[machine.base_register(first_instructions[-2].operands[0].reg)], CaseArgument) and first_instructions[-2].operands[1].type == capstone.x86.X86_OP_IMM:
            assert first_instructions[-1].mnemonic == 'jae'
            false_address = sum(map(lambda insn: insn.size, first_instructions)) + pointer.value
            true_address = first_instructions[-1].operands[0].imm

            false_pointer = StaticValue(value = false_address)
            true_pointer = StaticValue(value = true_address)

            parsed['interpretations'][pointer] = Case(scrutinee = scrutinee, bound_ptr = pointer, arms = [Pointer(true_pointer), Pointer(false_pointer)], tags = ['True', 'False'])

            if settings.opts.verbose:
                print()
                print("Found case arm:")
                print("    From case:", info_name)
                print("    Pattern: True")
            read_code(settings, parsed, true_pointer, copy.deepcopy(mach.stack), copy.deepcopy(mach.registers))

            if settings.opts.verbose:
                print("Found case arm:")
                print("    From case:", info_name)
                print("    Pattern: False")
            read_code(settings, parsed, false_pointer, copy.deepcopy(mach.stack), copy.deepcopy(mach.registers))
        else:
            read_code(settings, parsed, pointer, stack, {settings.rt.main_register: CaseArgument(inspection = pointer)})
            parsed['interpretations'][pointer] = Case(scrutinee = scrutinee, bound_ptr = pointer, arms = [parsed['interpretations'][pointer]], tags = ['_DEFAULT'])
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing case at", show.show_pretty(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm_from(settings, pointer.value):
            print("        " + show.show_instruction(insn))
        print()

def read_function_thunk(settings, parsed, pointer, main_register, num_args):
    if settings.opts.verbose:
        print("Found function/thunk!")

    assert isinstance(pointer, StaticValue)

    info_name = show.get_name_for_address(settings, pointer.value)
    if settings.opts.verbose:
        print("    Name:", show.demangle(info_name))
        print("    Arity:", num_args)

    if show.name_is_library(info_name):
        if settings.opts.verbose:
            print("    Library Defined!")
            print()
        return

    extra_stack = []
    registers = {}
    registers[settings.rt.main_register] = main_register
    for i in range(num_args):
        if i < len(settings.rt.arg_registers):
            registers[settings.rt.arg_registers[i]] = Argument(index = i, func = info_name)
        else:
            extra_stack.append(Argument(index = i, func = info_name))

    if num_args > 0:
        parsed['num-args'][pointer] = num_args

    read_code(settings, parsed, pointer, extra_stack, registers)

def read_code(settings, parsed, pointer, extra_stack, registers):
    try:
        assert isinstance(pointer, StaticValue)

        if pointer in parsed['interpretations']:
            if settings.opts.verbose:
                print("    Seen before!")
                print()
            return

        instructions = disasm_from(settings, pointer.value)

        registers[settings.rt.heap_register] = HeapPointer(heap_segment = pointer, index = -1, tag = 0)
        registers[settings.rt.stack_register] = StackPointer(index = -len(extra_stack))
        mach = machine.Machine(settings, parsed, extra_stack, registers)
        mach.simulate(instructions)

        stack = mach.stack[registers[settings.rt.stack_register].index:]
        registers = mach.registers

        parsed['heaps'][pointer] = mach.heap
        if settings.opts.verbose:
            print("    Heap:", list(map(lambda h: show.show_pretty(settings, h), mach.heap)))
            print("    Stack:", list(map(lambda s: show.show_pretty(settings, s), stack)))

        if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM and machine.base_register(instructions[-1].operands[0].mem.base) == settings.rt.stack_register:
            if settings.opts.verbose:
                print("    Interpretation: return", show.show_pretty(settings, registers[settings.rt.main_register]))
                print()

            parsed['interpretations'][pointer] = Pointer(registers[settings.rt.main_register])

            read_closure(settings, parsed, registers[settings.rt.main_register])
        else:
            worklist = []
            uses = []

            if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM:
                assert machine.base_register(instructions[-1].operands[0].mem.base) == settings.rt.main_register
                assert instructions[-1].operands[0].mem.disp == 0

                if settings.opts.verbose:
                    print("    Interpretation: evaluate", show.show_pretty(settings, registers[settings.rt.main_register]))

                stack_index = 0
                interpretation = Pointer(registers[settings.rt.main_register])
                worklist.append({'type': 'closure', 'pointer': registers[settings.rt.main_register]})
            elif instructions[-1].operands[0].type == capstone.x86.X86_OP_IMM:
                jmp_address = instructions[-1].operands[0].imm
                if jmp_address in settings.address_to_name and settings.address_to_name[jmp_address][:7] == 'stg_ap_':
                    func = settings.address_to_name[jmp_address]
                    if func.split('_')[2] == '0':
                        num_args = 0
                        arg_pattern = ''
                    else:
                        num_args = len(func.split('_')[2])
                        arg_pattern = func.split('_')[2]
                    called = registers[settings.rt.main_register]
                    worklist.append({'type': 'closure', 'pointer': called})
                    func_type = 'closure'
                else:
                    num_args = read_num_args(settings, jmp_address)
                    arg_pattern = 'p' * num_args
                    called = StaticValue(value = jmp_address)
                    worklist.append({'type': 'function/thunk', 'pointer': called, 'main-register': registers[settings.rt.main_register], 'num-args': num_args})
                    func_type = 'info'

                if settings.opts.verbose:
                    print("    Number of args:", num_args)

                args = []
                stack_index = num_args
                for reg, i in zip(settings.rt.arg_registers, range(num_args)):
                    args.append(registers[reg])
                    stack_index -= 1
                args += stack[:stack_index]

                if settings.opts.verbose:
                    print("    Interpretation: call", show.show_pretty(settings, called), "on", list(map(lambda s: show.show_pretty(settings, s), args)))
                interpretation = Apply(func_type = func_type, func = Pointer(called), args = list(map(Pointer, args)), pattern = arg_pattern)

                for arg, pat in zip(args, arg_pattern):
                    if pat == 'p':
                        worklist.append({'type': 'closure', 'pointer': arg})

            while stack_index < len(stack):
                assert isinstance(stack[stack_index], StaticValue)
                cont_name = show.get_name_for_address(settings, stack[stack_index].value)
                if cont_name[:7] == 'stg_ap_':
                    assert cont_name[-5:] == '_info'
                    arg_pattern = cont_name.split('_')[2]
                    num_extra_args = len(arg_pattern)
                    if settings.opts.verbose:
                        print("                    then apply the result to", list(map(lambda s: show.show_pretty(settings, s), stack[stack_index+1:][:num_extra_args])))
                    interpretation = Apply(func_type = 'closure', func = interpretation, args = list(map(Pointer, stack[stack_index+1:][:num_extra_args])), pattern = arg_pattern)
                    for arg in stack[stack_index+1:][:num_extra_args]:
                        worklist.append({'type': 'closure', 'pointer': arg})
                    stack_index += 1 + num_extra_args
                elif cont_name == 'stg_upd_frame_info' or cont_name == 'stg_bh_upd_frame_info':
                    if settings.opts.verbose:
                        print("                    then update the thunk at", show.show_pretty(settings, stack[stack_index + 1]))
                    stack_index += 2
                else:
                    if settings.opts.verbose:
                        print("                    then inspect using", show.show_pretty(settings, stack[stack_index]))
                    worklist.append({'type': 'case', 'pointer': stack[stack_index], 'stack': stack[stack_index:], 'scrutinee': interpretation})
                    interpretation = Pointer(stack[stack_index])
                    stack_index = len(stack)
            if settings.opts.verbose:
                print()

            parsed['interpretations'][pointer] = interpretation

            for work in worklist:
                if work['type'] == 'closure':
                    read_closure(settings, parsed, work['pointer'])
                elif work['type'] == 'function/thunk':
                    read_function_thunk(settings, parsed, work['pointer'], work['main-register'], work['num-args'])
                elif work['type'] == 'case':
                    read_case(settings, parsed, work['pointer'], work['stack'], work['scrutinee'])
                else:
                    assert False,"bad work in worklist"
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing code at", show.show_pretty(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm_from(settings, pointer.value):
            print("        " + show.show_instruction(insn))
        print()
