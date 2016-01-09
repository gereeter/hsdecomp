import argparse
import capstone
from elftools.elf.elffile import ELFFile

import optimize
import parse
import show
from hstypes import *

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Decompile a GHC-compiled Haskell program.')
    arg_parser.add_argument('file')
    arg_parser.add_argument('entry', default='Main_main_closure', nargs='?')
    arg_parser.add_argument('--ignore-strictness', action='store_true', dest='ignore_strictness')
    arg_parser.add_argument('--no-inline-once', action='store_false', dest='inline_once')
    arg_parser.add_argument('--no-abbreviate-library-names', action='store_false', dest='abbreviate_library_names')
    arg_parser.add_argument('--verbose', action='store_true', dest='verbose')
    opts = arg_parser.parse_args()

    elffile = ELFFile(open(opts.file, "rb"))

    if elffile.elfclass == 32:
        capstone_mode = capstone.CS_MODE_32
        runtime = Runtime(
            halfword_size = 2,
            halfword_struct = '<H',
            word_size = 4,
            word_struct = '<I',
            stack_register = capstone.x86.X86_REG_RBP,
            heap_register = capstone.x86.X86_REG_RDI,
            main_register = capstone.x86.X86_REG_RSI,
            arg_registers = []
        )
    elif elffile.elfclass == 64:
        capstone_mode = capstone.CS_MODE_64
        runtime = Runtime(
            halfword_size = 4,
            halfword_struct = '<I',
            word_size = 8,
            word_struct = '<Q',
            stack_register = capstone.x86.X86_REG_RBP,
            heap_register = capstone.x86.X86_REG_R12,
            main_register = capstone.x86.X86_REG_RBX,
            arg_registers = [capstone.x86.X86_REG_R14, capstone.x86.X86_REG_RSI, capstone.x86.X86_REG_RDI, capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9]
        )

    settings = Settings(
        opts = opts,
        rt = runtime,
        name_to_address = {},
        address_to_name = {},
        binary = open(opts.file, "rb").read(),
        capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone_mode),
        text_offset = elffile.get_section_by_name(b'.text')['sh_offset'] - elffile.get_section_by_name(b'.text')['sh_addr'],
        data_offset = elffile.get_section_by_name(b'.data')['sh_offset'] - elffile.get_section_by_name(b'.data')['sh_addr'],
        rodata_offset = elffile.get_section_by_name(b'.rodata')['sh_offset'] - elffile.get_section_by_name(b'.rodata')['sh_addr']
    )

    symtab = elffile.get_section_by_name(b'.symtab')
    for sym in symtab.iter_symbols():
        try:
            name = str(sym.name, 'ascii')
            offset = sym['st_value']
            settings.name_to_address[name] = offset
            settings.address_to_name[offset] = name
        except:
            pass

    settings.capstone.detail = True

    parsed = {}
    parsed['heaps'] = {}
    parsed['interpretations'] = {}
    parsed['num-args'] = {}

    entry_pointer = StaticValue(value = settings.name_to_address[opts.entry])

    parse.read_closure(settings, parsed, entry_pointer)

    optimize.run_destroy_empty_apply(parsed)

    if opts.ignore_strictness:
        optimize.run_destroy_strictness(parsed)

    optimize.run_inline_cheap(parsed)

    if opts.inline_once:
        optimize.run_inline_once(parsed)

    function_worklist = [entry_pointer]
    seen = {}
    while len(function_worklist) > 0:
        worklist = [function_worklist.pop()]
        started = False

        while len(worklist) > 0:
            pointer = worklist.pop()
            if pointer in seen or not pointer in parsed['interpretations']:
                continue
            else:
                if len(seen) > 0 and not started:
                    print()
                seen[pointer] = None
                started = True

            pretty = show.show_pretty(settings, pointer)
            lhs = pretty
            if pointer in parsed['num-args']:
                for i in range(parsed['num-args'][pointer]):
                    lhs += " "
                    lhs += pretty
                    lhs += "_arg_"
                    lhs += str(i)
            print(lhs, "=", show.show_pretty_interpretation(settings, parsed['interpretations'][pointer]))

            optimize.foreach_use(parsed['interpretations'][pointer], lambda interp: (function_worklist if interp in parsed['num-args'] else worklist).append(interp))
