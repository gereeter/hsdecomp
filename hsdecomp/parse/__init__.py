import sys
import copy
import capstone

from hsdecomp import ptrutil, machine, show
from hsdecomp.parse import disasm, info
from hsdecomp.types import *

def interp_args(args, arg_pattern):
    ret = []
    arg_idx = 0
    for pat in arg_pattern:
        if pat == 'p':
            ret.append(Pointer(args[arg_idx].untagged))
            arg_idx += 1
        elif pat == 'n':
            ret.append(args[arg_idx].untagged.value + args[arg_idx].tag)
            arg_idx += 1
        elif pat == 'v':
            ret.append(None)
    return ret

def read_closure(settings, worklist, heaps, pointer):
    try:
        info_pointer = ptrutil.dereference(settings, pointer, heaps, []).untagged
        assert isinstance(info_pointer, StaticValue)
        info_address = info_pointer.value

        info_type = info.read_closure_type(settings, info_address)
        if settings.opts.verbose:
            print("    Type:", info_type)

        if info_type[:11] == 'constructor':
            num_ptrs = ptrutil.read_half_word(settings, settings.text_offset + info_address - settings.rt.halfword.size*4)
            num_non_ptrs = ptrutil.read_half_word(settings, settings.text_offset + info_address - settings.rt.halfword.size*3)

            args = []
            arg_pointer = ptrutil.make_tagged(settings, pointer)._replace(tag = 0)
            for i in range(num_ptrs + num_non_ptrs):
                arg_pointer = ptrutil.pointer_offset(settings, arg_pointer, settings.rt.word.size);
                args.append(ptrutil.dereference(settings, arg_pointer.untagged, heaps, []))

            arg_pattern = 'p' * num_ptrs + 'n' * num_non_ptrs

            for arg in args[:num_ptrs]:
                worklist.append(ClosureWork(heaps = heaps, pointer = arg.untagged))

            return Apply(func = Pointer(info_pointer), func_type = 'constructor', args = interp_args(args, arg_pattern), pattern = arg_pattern)
        elif info_type[:11] == 'indirection':
            tagged = ptrutil.make_tagged(settings, pointer)._replace(tag = 0)
            offset = ptrutil.pointer_offset(settings, tagged, settings.rt.word.size)
            new_ptr = ptrutil.dereference(settings, offset.untagged, heaps, [])

            if settings.opts.verbose:
                print()

            worklist.append(ClosureWork(heaps = heaps, pointer = new_ptr.untagged))
            return Pointer(new_ptr.untagged)
        elif info_type[:8] == 'function':
            arg_pattern = info.read_arg_pattern(settings, info_address)
        else:
            arg_pattern = ''

        worklist.append(FunctionThunkWork(heaps = heaps, address = info_address, main_register = ptrutil.make_tagged(settings, pointer)._replace(tag = len(arg_pattern)), arg_pattern = arg_pattern))
        return Pointer(info_pointer)

    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error when processing closure at", show.show_pretty_pointer(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    No Disassembly Available")
        print()
        return UnknownInterpretation()

def read_function_thunk(settings, worklist, heaps, address, main_register, arg_pattern):
    extra_stack = []
    registers = {}
    registers[settings.rt.main_register] = main_register
    for i in range(len(arg_pattern)):
        if arg_pattern[i] != 'v':
            if i < len(settings.rt.arg_registers):
                registers[settings.rt.arg_registers[i]] = ptrutil.make_tagged(settings, Argument(index = i, func = address))
            else:
                extra_stack.append(ptrutil.make_tagged(settings, Argument(index = i, func = address)))

    body = read_code(settings, worklist, heaps, address, extra_stack, registers)
    if arg_pattern == '':
        return body
    else:
        return Lambda(func = address, arg_pattern = arg_pattern, body = body)

def gather_case_arms(settings, heaps, address, min_tag, max_tag, initial_stack, initial_registers, original_stack, original_inspection, path):
    mach = machine.Machine(settings, heaps, copy.deepcopy(initial_stack), copy.deepcopy(initial_registers))
    first_instructions = list(disasm.disasm_from_until(settings, address, lambda insn: insn.group(capstone.x86.X86_GRP_JUMP)))
    mach.simulate(first_instructions)

    if first_instructions[-2].mnemonic == 'cmp' and isinstance(mach.load(first_instructions[-2].operands[0]), Tagged) and isinstance(mach.load(first_instructions[-2].operands[0]).untagged, Offset) and isinstance(mach.load(first_instructions[-2].operands[0]).untagged.base, CasePointer) and first_instructions[-2].operands[1].type == capstone.x86.X86_OP_IMM:
        assert first_instructions[-1].mnemonic == 'jae'
        small_address = sum(map(lambda insn: insn.size, first_instructions)) + address
        large_address = first_instructions[-1].operands[0].imm

        arms_small, tags_small, stacks_small, regs_small = gather_case_arms(settings, heaps, small_address, min_tag, first_instructions[-2].operands[1].imm - 1, mach.stack, mach.registers, original_stack, original_inspection, path + [address])
        arms_large, tags_large, stacks_large, regs_large = gather_case_arms(settings, heaps, large_address, first_instructions[-2].operands[1].imm, max_tag, mach.stack, mach.registers, original_stack, original_inspection, path + [address])

        arms = arms_small + arms_large
        tags = tags_small + tags_large
        stacks = stacks_small + stacks_large
        registers = regs_small + regs_large
    else:
        arms = [address]
        if min_tag == max_tag:
            tag = NumericTag(value = min_tag)
        else:
            tag = DefaultTag()
        tags = [tag]

        # Resimulate the steps taken to get to this point with the correctly tagged CasePointer
        mach = machine.Machine(settings, heaps, copy.deepcopy(original_stack), {
            settings.rt.main_register: ptrutil.make_tagged(settings, Offset(base = CasePointer(inspection = original_inspection, matched_tag = tag), index = 0))._replace(tag = min_tag),
            settings.rt.stack_register: ptrutil.make_tagged(settings, Offset(base = StackPointer(), index = -len(original_stack)))
        })
        for step in path:
            mach.simulate(disasm.disasm_from_until(settings, step, lambda insn: insn.group(capstone.x86.X86_GRP_JUMP)))

        stacks = [mach.stack]
        registers = [mach.registers]

    return arms, tags, stacks, registers

def read_case(settings, worklist, heaps, pointer, stack, scrutinee):
    try:
        if settings.opts.verbose:
            print("Found case inspection!")

        info_name = show.get_name_for_address(settings, pointer.value)
        if settings.opts.verbose:
            print("    Name:", show.demangle(info_name))

        arms, tags, stacks, registers = gather_case_arms(settings, heaps, pointer.value, 1, settings.rt.word.size - 1, stack, {
            settings.rt.main_register: ptrutil.make_tagged(settings, Offset(base = CasePointer(inspection = pointer, matched_tag = DefaultTag()), index = 0)),
            settings.rt.stack_register: ptrutil.make_tagged(settings, Offset(base = StackPointer(), index = -len(stack)))
        }, stack, pointer, [])

        interp_arms = []
        for arm, tag, stack, regs in zip(arms, tags, stacks, registers):
            if settings.opts.verbose:
                print()
                print("Found case arm:")
                print("    From case:", info_name)
                print("    Pattern:", tag)
            interp_arms.append(read_code(settings, worklist, heaps, arm, stack, regs))

        return Case(scrutinee = scrutinee, bound_ptr = pointer, arms = interp_arms, tags = tags)
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing case at", show.show_pretty_pointer(settings, pointer))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm.disasm_from(settings, pointer.value):
            print("        " + show.show_instruction(insn))
        print()
        return UnknownInterpretation()

def read_code(settings, worklist, heaps, address, extra_stack, registers):
    try:
        instructions = list(disasm.disasm_from(settings, address))

        registers[settings.rt.heap_register] = ptrutil.make_tagged(settings, Offset(base = HeapPointer(id = len(heaps), owner = address), index = -1))
        registers[settings.rt.stack_register] = ptrutil.make_tagged(settings, Offset(base = StackPointer(), index = -len(extra_stack)))
        mach = machine.Machine(settings, heaps, extra_stack, registers)
        mach.simulate(instructions)

        registers = mach.registers
        stack = mach.stack[registers[settings.rt.stack_register].untagged.index+len(mach.stack):]

        new_heaps = heaps + [mach.heap]

        if settings.opts.verbose:
            print("    Heap:", list(map(lambda h: show.show_pretty_value(settings, h), mach.heap)))
            print("    Stack:", list(map(lambda s: show.show_pretty_value(settings, s), stack)))

        if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM and machine.base_register(instructions[-1].operands[0].mem.base) == settings.rt.stack_register:
            if settings.opts.verbose:
                print("    Interpretation: return", show.show_pretty_value(settings, registers[settings.rt.main_register]))

            returned = registers[settings.rt.main_register].untagged

            interpretation = Pointer(returned)
            worklist.append(ClosureWork(heaps = new_heaps, pointer = returned))
        else:
            uses = []

            if instructions[-1].operands[0].type == capstone.x86.X86_OP_MEM:
                assert machine.base_register(instructions[-1].operands[0].mem.base) == settings.rt.main_register
                assert instructions[-1].operands[0].mem.disp == 0

                if settings.opts.verbose:
                    print("    Interpretation: evaluate", show.show_pretty_value(settings, registers[settings.rt.main_register]))

                evaled = registers[settings.rt.main_register].untagged

                stack_index = 0
                interpretation = Pointer(evaled)
                worklist.append(ClosureWork(heaps = new_heaps, pointer = evaled))
            elif instructions[-1].operands[0].type == capstone.x86.X86_OP_IMM:
                jmp_address = instructions[-1].operands[0].imm
                if jmp_address in settings.address_to_name and settings.address_to_name[jmp_address][:7] == 'stg_ap_':
                    func = settings.address_to_name[jmp_address]
                    if func.split('_')[2] == '0':
                        arg_pattern = ''
                    else:
                        arg_pattern = func.split('_')[2]
                    called = registers[settings.rt.main_register].untagged
                    worklist.append(ClosureWork(heaps = new_heaps, pointer = called))
                    func_type = 'closure'
                else:
                    arg_pattern = info.read_arg_pattern(settings, jmp_address)
                    called = StaticValue(value = jmp_address)
                    worklist.append(FunctionThunkWork(heaps = new_heaps, address = jmp_address, main_register = registers[settings.rt.main_register], arg_pattern = arg_pattern))
                    func_type = 'info'

                num_args = sum(1 for e in filter(lambda pat: pat != 'v', arg_pattern))

                if settings.opts.verbose:
                    print("    Number of non-void args:", num_args)
                    print("    Called:", show.show_pretty_pointer(settings, called))
                    print("    Arg pattern:", arg_pattern)

                args = []
                stack_index = num_args
                for reg, i in zip(settings.rt.arg_registers, range(num_args)):
                    args.append(registers[reg])
                    stack_index -= 1
                args += stack[:stack_index]

                if settings.opts.verbose:
                    print("    Interpretation: call", show.show_pretty_pointer(settings, called), "on", list(map(lambda s: show.show_pretty_value(settings, s), args)))
                interpretation = Apply(func_type = func_type, func = Pointer(called), args = interp_args(args, arg_pattern), pattern = arg_pattern)

                for arg, pat in zip(args, arg_pattern):
                    if pat == 'p':
                        worklist.append(ClosureWork(heaps = new_heaps, pointer = arg.untagged))

            while stack_index < len(stack):
                assert isinstance(stack[stack_index].untagged, StaticValue)
                cont_name = show.get_name_for_address(settings, stack[stack_index].untagged.value)
                if cont_name[:7] == 'stg_ap_':
                    assert cont_name[-5:] == '_info'
                    arg_pattern = cont_name.split('_')[2]
                    num_extra_args = sum(1 for e in filter(lambda pat: pat != 'v', arg_pattern))
                    if settings.opts.verbose:
                        print("                    then apply the result to", list(map(lambda s: show.show_pretty_value(settings, s), stack[stack_index+1:][:num_extra_args])))
                    interpretation = Apply(func_type = 'closure', func = interpretation, args = interp_args(stack[stack_index+1:][:num_extra_args], arg_pattern), pattern = arg_pattern)
                    for arg in stack[stack_index+1:][:num_extra_args]:
                        worklist.append(ClosureWork(heaps = new_heaps, pointer = arg.untagged))
                    stack_index += 1 + num_extra_args
                elif cont_name == 'stg_upd_frame_info' or cont_name == 'stg_bh_upd_frame_info':
                    if settings.opts.verbose:
                        print("                    then update the thunk at", show.show_pretty_value(settings, stack[stack_index + 1]))
                    stack_index += 2
                else:
                    if settings.opts.verbose:
                        print("                    then inspect using", show.show_pretty_value(settings, stack[stack_index]))
                        print()
                    interpretation = read_case(settings, worklist, new_heaps, stack[stack_index].untagged, stack[stack_index:], interpretation)
                    stack_index = len(stack)
            if settings.opts.verbose:
                print()

        return interpretation
    except:
        e_type, e_obj, e_tb = sys.exc_info()
        print("Error in processing code at", show.show_pretty_address(settings, address))
        print("    Error:", e_obj)
        print("    Error Location:", e_tb.tb_lineno)
        print("    Disassembly:")
        for insn in disasm.disasm_from(settings, address):
            print("        " + show.show_instruction(insn))
        print()
        return UnknownInterpretation()
