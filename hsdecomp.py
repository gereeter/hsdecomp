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

    parsed = {}
    parsed['opts'] = arg_parser.parse_args()

    parsed['name-to-address'] = {}
    parsed['address-to-name'] = {}

    elffile = ELFFile(open(parsed['opts'].file, "rb"))
    symtab = elffile.get_section_by_name(b'.symtab')
    for sym in symtab.iter_symbols():
        try:
            name = str(sym.name, 'ascii')
            offset = sym['st_value']
            parsed['name-to-address'][name] = offset
            parsed['address-to-name'][offset] = name
        except:
            pass

    if elffile.elfclass == 32:
        capstone_mode = capstone.CS_MODE_32
        parsed['halfword-size'] = 2
        parsed['halfword-struct'] = '<H'
        parsed['word-size'] = 4
        parsed['word-struct'] = '<I'
        parsed['stack-register'] = capstone.x86.X86_REG_RBP
        parsed['heap-register'] = capstone.x86.X86_REG_RDI
        parsed['main-register'] = capstone.x86.X86_REG_RSI
        parsed['arg-registers'] = []
    elif elffile.elfclass == 64:
        capstone_mode = capstone.CS_MODE_64
        parsed['halfword-size'] = 4
        parsed['halfword-struct'] = '<I'
        parsed['word-size'] = 8
        parsed['word-struct'] = '<Q'
        parsed['stack-register'] = capstone.x86.X86_REG_RBP
        parsed['heap-register'] = capstone.x86.X86_REG_R12
        parsed['main-register'] = capstone.x86.X86_REG_RBX
        parsed['arg-registers'] = [capstone.x86.X86_REG_R14, capstone.x86.X86_REG_RSI, capstone.x86.X86_REG_RDI, capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9]

    parsed['binary'] = open(parsed['opts'].file, "rb").read()
    parsed['capstone'] = capstone.Cs(capstone.CS_ARCH_X86, capstone_mode)
    parsed['capstone'].detail = True

    parsed['text-offset'] = elffile.get_section_by_name(b'.text')['sh_offset'] - elffile.get_section_by_name(b'.text')['sh_addr']
    parsed['data-offset'] = elffile.get_section_by_name(b'.data')['sh_offset'] - elffile.get_section_by_name(b'.data')['sh_addr']
    parsed['rodata-offset'] = elffile.get_section_by_name(b'.rodata')['sh_offset'] - elffile.get_section_by_name(b'.rodata')['sh_addr']

    parsed['heaps'] = {}
    parsed['interpretations'] = {}
    parsed['num-args'] = {}

    entry_pointer = StaticValue(value = parsed['name-to-address'][parsed['opts'].entry])

    parse.read_closure(parsed, entry_pointer)

    optimize.run_destroy_empty_apply(parsed)

    if parsed['opts'].ignore_strictness:
        optimize.run_destroy_strictness(parsed)

    if parsed['opts'].inline_once:
        optimize.run_inline_once(parsed)

    optimize.run_inline_cheap(parsed)

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

            pretty = show.show_pretty(parsed, pointer)
            lhs = pretty
            if pointer in parsed['num-args']:
                for i in range(parsed['num-args'][pointer]):
                    lhs += " "
                    lhs += pretty
                    lhs += "_arg_"
                    lhs += str(i)
            print(lhs, "=", show.show_pretty_interpretation(parsed, parsed['interpretations'][pointer]))

            optimize.foreach_use(parsed['interpretations'][pointer], lambda interp: (function_worklist if interp in parsed['num-args'] else worklist).append(interp))
