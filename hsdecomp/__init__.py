import argparse
import capstone
from elftools.elf.elffile import ELFFile

from hsdecomp import optimize, parse, show, infer
from hsdecomp.types import *

def main():
    arg_parser = argparse.ArgumentParser(description='Decompile a GHC-compiled Haskell program.')
    arg_parser.add_argument('file')
    arg_parser.add_argument('entry', default='Main_main_closure', nargs='?')
    arg_parser.add_argument('--ignore-strictness', action='store_true', dest='ignore_strictness')
    arg_parser.add_argument('--no-inline-once', action='store_false', dest='inline_once')
    arg_parser.add_argument('--show-types', action='store_true', dest='show_types')
    arg_parser.add_argument('--no-abbreviate-library-names', action='store_false', dest='abbreviate_library_names')
    arg_parser.add_argument('--verbose', action='store_true', dest='verbose')
    opts = arg_parser.parse_args()

    elffile = ELFFile(open(opts.file, "rb"))

    if elffile.elfclass == 32:
        capstone_mode = capstone.CS_MODE_32
        runtime = Runtime(
            halfword = WordDesc(size = 2, lg_size = 1, struct = '<H'),
            word = WordDesc(size = 4, lg_size = 2, struct = '<I'),
            stack_register = capstone.x86.X86_REG_RBP,
            heap_register = capstone.x86.X86_REG_RDI,
            main_register = capstone.x86.X86_REG_RSI,
            arg_registers = []
        )
    elif elffile.elfclass == 64:
        capstone_mode = capstone.CS_MODE_64
        runtime = Runtime(
            halfword = WordDesc(size = 4, lg_size = 2, struct = '<I'),
            word = WordDesc(size = 8, lg_size = 3, struct = '<Q'),
            stack_register = capstone.x86.X86_REG_RBP,
            heap_register = capstone.x86.X86_REG_R12,
            main_register = capstone.x86.X86_REG_RBX,
            arg_registers = [capstone.x86.X86_REG_R14, capstone.x86.X86_REG_RSI, capstone.x86.X86_REG_RDI, capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9]
        )

    settings = Settings(
        opts = opts,
        rt = runtime,
        version = (7, 10, 3),
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

    parsed_version = parse.read_version(settings)
    if parsed_version != None:
        settings = settings._replace(version = parsed_version)

    parsed = {}
    parsed['heaps'] = {}
    parsed['interpretations'] = {}
    parsed['arg-pattern'] = {}
    parsed['types'] = {}

    entry_pointer = StaticValue(value = settings.name_to_address[opts.entry])

    parse.read_closure(settings, parsed, entry_pointer)

    for ptr in parsed['interpretations']:
         infer.infer_type_for(settings, parsed, ptr)

    infer.run_rename_tags(settings, parsed)

    optimize.run_destroy_empty_apply(parsed)
    if opts.ignore_strictness:
        optimize.run_destroy_strictness(parsed)
    optimize.run_delete_unused(parsed, entry_pointer)
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
            if pointer in parsed['arg-pattern']:
                for i, pat in enumerate(parsed['arg-pattern'][pointer]):
                    lhs += " "
                    if pat == 'v':
                        lhs += "state#"
                    else:
                        lhs += pretty
                        lhs += "_arg_"
                        lhs += str(i)

            if settings.opts.show_types and pointer in parsed['types']:
                print(pretty, "::", show.show_pretty_type(settings, parsed['types'][pointer], False))
            print(lhs, "=", show.show_pretty_interpretation(settings, parsed['interpretations'][pointer]))

            optimize.foreach_use(parsed['interpretations'][pointer], lambda interp: (function_worklist if interp in parsed['arg-pattern'] else worklist).append(interp))
