import argparse

from hsdecomp import optimize, parse, show, infer, metadata
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

    settings = metadata.read_settings(opts)

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
