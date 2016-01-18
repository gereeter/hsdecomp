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

    # Parse the binary

    entry_pointer = StaticValue(value = settings.name_to_address[opts.entry])

    parsed = {}
    parsed['interpretations'] = {}
    parsed['types'] = {}
    parse.read_closure(settings, parsed, [], entry_pointer)

    # Analyze the inferred code for type information to make case statements clearer

    for ptr in parsed['interpretations']:
         infer.infer_type_for(settings, parsed, ptr)
    infer.run_rename_tags(settings, parsed)

    # Clean things up for human consumption

    optimize.run_destroy_empty_apply(parsed['interpretations'])
    if opts.ignore_strictness:
        optimize.run_destroy_strictness(parsed['interpretations'])
    parsed['interpretations'] = optimize.run_delete_unused(parsed['interpretations'], entry_pointer)
    optimize.run_inline_cheap(parsed['interpretations'])
    if opts.inline_once:
        optimize.run_inline_once(parsed['interpretations'])

    # Display our parsed file

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

            pretty = show.show_pretty_pointer(settings, pointer)
            lhs = pretty
            if settings.opts.show_types and pointer in parsed['types']:
                print(pretty, "::", show.show_pretty_type(settings, parsed['types'][pointer], False))
            print(lhs, "=", show.show_pretty_interpretation(settings, parsed['interpretations'][pointer]))

            optimize.foreach_use(parsed['interpretations'][pointer], lambda ptr: (function_worklist if ptr in parsed['interpretations'] and isinstance(parsed['interpretations'][ptr], Lambda) else worklist).append(ptr))
