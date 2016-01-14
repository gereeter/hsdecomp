import sys
import struct
import copy
import capstone

from hsdecomp import ptrutil, machine, show
from hsdecomp.types import *

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

def read_arg_pattern(settings, address):
    num_args = read_num_args(settings, address)
    func_type = read_function_type(settings, address)
    assert num_args >= len(func_type)
    return func_type + 'v' * (num_args - len(func_type))

def read_num_args(settings, address):
    return ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*5)

def read_function_type(settings, address):
    type_table = {
        3: '',
        4: 'n',
        5: 'p',
        12: 'nn',
        13: 'np',
        14: 'pn',
        15: 'pp',
        16: 'nnn',
        17: 'nnp',
        18: 'npn',
        19: 'npp',
        20: 'pnn',
        21: 'pnp',
        22: 'ppn',
        23: 'ppp',
        24: 'pppp',
        25: 'ppppp',
        26: 'pppppp',
        27: 'ppppppp',
        28: 'pppppppp'
    }
    type = ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*6)
    if type >= 12 and settings.version < (7, 8, 0):
        # Introduction of vector arguments
        type += 3
    if type in type_table:
        return type_table[type]
    elif type == 0:
        bitmap = ptrutil.read_word(settings, settings.text_offset + address - settings.rt.word.size*5)
        size = bitmap & (settings.word.size - 1)
        bits = bitmap >> settings.word.lg_size
        ret = ''
        for i in range(size):
            if bits % 2 == 0:
                ret += 'p'
            else:
                ret += 'n'
            bits //= 2
        return ret
    else:
       # TODO: Read large bitmaps
       assert False, "unknown function type"

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

        untagged_pointer = pointer

        if isinstance(pointer, Offset):
            pointer = Tagged(untagged = pointer, tag = 0)

        if settings.opts.verbose:
            print("Found closure:")
            print("    Pointer:", show.show_pretty(settings, pointer))

        if isinstance(pointer, StaticValue) and show.name_is_library(show.get_name_for_address(settings, pointer.value)):
            if settings.opts.verbose:
                print("    Library defined!")
                print()
            return

        info_pointer = ptrutil.dereference(settings, parsed, pointer, [])
        assert isinstance(info_pointer, StaticValue)

        info_type = read_closure_type(settings, info_pointer.value)
        if info_type[:11] == 'constructor':
            num_ptrs = ptrutil.read_half_word(settings, settings.text_offset + info_pointer.value - settings.rt.halfword.size*4)
            num_non_ptrs = ptrutil.read_half_word(settings, settings.text_offset + info_pointer.value - settings.rt.halfword.size*3)

            args = []
            arg_pointer = pointer
            for i in range(num_ptrs + num_non_ptrs):
                arg_pointer = ptrutil.pointer_offset(settings, arg_pointer, settings.rt.word.size);
                args.append(ptrutil.dereference(settings, parsed, arg_pointer, []))

            parsed['interpretations'][untagged_pointer] = Apply(func = Pointer(info_pointer), func_type = 'constructor', args = list(map(Pointer, args)), pattern = 'p' * num_ptrs + 'n' * num_non_ptrs)
            if settings.opts.verbose:
                print()

            for arg in args[:num_ptrs]:
                read_closure(settings, parsed, arg)

            return
        elif info_type[:8] == 'function':
            arg_pattern = read_arg_pattern(settings, info_pointer.value)
        else:
            arg_pattern = ''

        if settings.opts.verbose:
            print()

        parsed['interpretations'][untagged_pointer] = Pointer(info_pointer)

        read_function_thunk(settings, parsed, info_pointer, ptrutil.retag(settings, pointer, len(arg_pattern)), arg_pattern)
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error when processing closure at", show.show_pretty(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    No Disassembly Available")
        print()

def gather_case_arms(settings, parsed, address, min_tag, max_tag, initial_stack, initial_registers):
    mach = machine.Machine(settings, parsed, copy.deepcopy(initial_stack), copy.deepcopy(initial_registers))
    first_instructions = disasm_from_until(settings, address, lambda insn: insn.group(capstone.x86.X86_GRP_JUMP))
    mach.simulate(first_instructions)

    if first_instructions[-2].mnemonic == 'cmp' and isinstance(mach.load(first_instructions[-2].operands[0]), CaseArgument) and first_instructions[-2].operands[1].type == capstone.x86.X86_OP_IMM:
        assert first_instructions[-1].mnemonic == 'jae'
        small_address = sum(map(lambda insn: insn.size, first_instructions)) + address
        large_address = first_instructions[-1].operands[0].imm

        arms_small, tags_small, stacks_small, regs_small = gather_case_arms(settings, parsed, small_address, min_tag, first_instructions[-2].operands[1].imm - 1, copy.deepcopy(mach.stack), copy.deepcopy(mach.registers))
        arms_large, tags_large, stacks_large, regs_large = gather_case_arms(settings, parsed, large_address, first_instructions[-2].operands[1].imm, max_tag, copy.deepcopy(mach.stack), copy.deepcopy(mach.registers))

        arms = arms_small + arms_large
        tags = tags_small + tags_large
        stacks = stacks_small + stacks_large
        registers = regs_small + regs_large
    else:
        arms = [StaticValue(value = address)]
        if min_tag == max_tag:
            tags = [NumericTag(value = min_tag)]
        else:
            tags = [DefaultTag()]
        stacks = [initial_stack]
        registers = [initial_registers]

    return arms, tags, stacks, registers

def read_case(settings, parsed, pointer, stack, scrutinee):
    try:
        if settings.opts.verbose:
            print("Found case inspection!")

        info_name = show.get_name_for_address(settings, pointer.value)
        if settings.opts.verbose:
            print("    Name:", show.demangle(info_name))

        arms, tags, stacks, registers = gather_case_arms(settings, parsed, pointer.value, 1, settings.rt.word.size - 1, stack, {
            settings.rt.main_register: CaseArgument(inspection = pointer),
            settings.rt.stack_register: Tagged(untagged = Offset(base = StackPointer(), index = -len(stack)), tag = 0)
        })

        for arm, tag, stack, regs in zip(arms, tags, stacks, registers):
            if settings.opts.verbose:
                print()
                print("Found case arm:")
                print("    From case:", info_name)
                print("    Pattern:", tag)
            read_code(settings, parsed, arm, stack, regs)

        parsed['interpretations'][pointer] = Case(scrutinee = scrutinee, bound_ptr = pointer, arms = list(map(lambda ptr: parsed['interpretations'][ptr], arms)), tags = tags)
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing case at", show.show_pretty(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm_from(settings, pointer.value):
            print("        " + show.show_instruction(insn))
        print()

def read_function_thunk(settings, parsed, pointer, main_register, arg_pattern):
    if settings.opts.verbose:
        print("Found function/thunk!")

    assert isinstance(pointer, StaticValue)

    info_name = show.get_name_for_address(settings, pointer.value)
    if settings.opts.verbose:
        print("    Name:", show.demangle(info_name))
        print("    Arg pattern:", arg_pattern)

    if show.name_is_library(info_name):
        if settings.opts.verbose:
            print("    Library Defined!")
            print()
        return

    extra_stack = []
    registers = {}
    registers[settings.rt.main_register] = main_register
    for i in range(len(arg_pattern)):
        if arg_pattern[i] != 'v':
            if i < len(settings.rt.arg_registers):
                registers[settings.rt.arg_registers[i]] = Argument(index = i, func = info_name)
            else:
                extra_stack.append(Argument(index = i, func = info_name))

    if arg_pattern != '':
        parsed['arg-pattern'][pointer] = arg_pattern

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

        registers[settings.rt.heap_register] = Tagged(untagged = Offset(base = HeapPointer(heap_segment = pointer), index = -1), tag = 0)
        registers[settings.rt.stack_register] = Tagged(untagged = Offset(base = StackPointer(), index = -len(extra_stack)), tag = 0)
        mach = machine.Machine(settings, parsed, extra_stack, registers)
        mach.simulate(instructions)

        registers = mach.registers
        stack = mach.stack[registers[settings.rt.stack_register].untagged.index+len(mach.stack):]

        parsed['heaps'][pointer] = mach.heap
        if settings.opts.verbose:
            print("    Heap:", list(map(lambda h: show.show_pretty(settings, h), mach.heap)))
            print("    Stack:", list(map(lambda s: show.show_pretty(settings, s), stack)))

        if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM and machine.base_register(instructions[-1].operands[0].mem.base) == settings.rt.stack_register:
            if settings.opts.verbose:
                print("    Interpretation: return", show.show_pretty(settings, registers[settings.rt.main_register]))
                print()

            returned = ptrutil.detag(settings, registers[settings.rt.main_register])

            parsed['interpretations'][pointer] = Pointer(returned)
            read_closure(settings, parsed, returned)
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
                        arg_pattern = ''
                    else:
                        arg_pattern = func.split('_')[2]
                    called = ptrutil.detag(settings, registers[settings.rt.main_register])
                    worklist.append({'type': 'closure', 'pointer': called})
                    func_type = 'closure'
                else:
                    arg_pattern = read_arg_pattern(settings, jmp_address)
                    called = StaticValue(value = jmp_address)
                    worklist.append({'type': 'function/thunk', 'pointer': called, 'main-register': registers[settings.rt.main_register], 'arg-pattern': arg_pattern})
                    func_type = 'info'

                num_args = sum(1 for e in filter(lambda pat: pat != 'v', arg_pattern))

                if settings.opts.verbose:
                    print("    Number of non-void args:", num_args)
                    print("    Called:", show.show_pretty(settings, called))
                    print("    Arg pattern:", arg_pattern)

                args = []
                stack_index = num_args
                for reg, i in zip(settings.rt.arg_registers, range(num_args)):
                    if reg in registers:
                        args.append(ptrutil.detag(settings, registers[reg]))
                    else:
                        args.append(UnknownValue())
                    stack_index -= 1
                args += map(lambda ptr: ptrutil.detag(settings, ptr), stack[:stack_index])

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
                    num_extra_args = sum(1 for e in filter(lambda pat: pat != 'v', arg_pattern))
                    if settings.opts.verbose:
                        print("                    then apply the result to", list(map(lambda s: show.show_pretty(settings, s), stack[stack_index+1:][:num_extra_args])))
                    interpretation = Apply(func_type = 'closure', func = interpretation, args = list(map(lambda ptr: Pointer(ptrutil.detag(settings, ptr)), stack[stack_index+1:][:num_extra_args])), pattern = arg_pattern)
                    for arg in stack[stack_index+1:][:num_extra_args]:
                        worklist.append({'type': 'closure', 'pointer': ptrutil.detag(settings, arg)})
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
                    read_function_thunk(settings, parsed, work['pointer'], work['main-register'], work['arg-pattern'])
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
