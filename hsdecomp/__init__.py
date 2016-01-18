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

    interpretations = {}
    parse.read_closure(settings, interpretations, [], entry_pointer)

    # Analyze the inferred code for type information to make case statements clearer

    types = {}
    for ptr in interpretations:
         infer.infer_type_for(settings, interpretations, types, ptr)
    infer.run_rename_tags(settings, interpretations, types)

    # Clean things up for human consumption

    optimize.run_destroy_empty_apply(interpretations)
    if opts.ignore_strictness:
        optimize.run_destroy_strictness(interpretations)
    interpretations = optimize.run_delete_unused(interpretations, entry_pointer)
    optimize.run_inline_cheap(interpretations)
    if opts.inline_once:
        optimize.run_inline_once(interpretations)

    # Display our parsed file

    function_worklist = [entry_pointer]
    seen = {}
    while len(function_worklist) > 0:
        worklist = [function_worklist.pop()]
        started = False

        while len(worklist) > 0:
            pointer = worklist.pop()
            if pointer in seen or not pointer in interpretations:
                continue
            else:
                if len(seen) > 0 and not started:
                    print()
                seen[pointer] = None
                started = True

            pretty = show.show_pretty_pointer(settings, pointer)
            lhs = pretty
            if settings.opts.show_types and pointer in types:
                print(pretty, "::", show.show_pretty_type(settings, types[pointer], False))
            print(lhs, "=", show.show_pretty_interpretation(settings, interpretations[pointer]))

            optimize.foreach_use(interpretations[pointer], lambda ptr: (function_worklist if ptr in interpretations and isinstance(interpretations[ptr], Lambda) else worklist).append(ptr))
