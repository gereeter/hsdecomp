import argparse

from hsdecomp import optimize, parse, show, infer, metadata
from hsdecomp.types import *

def main():
    arg_parser = argparse.ArgumentParser(description='Decompile a GHC-compiled Haskell program.')
    arg_parser.add_argument('file')
    arg_parser.add_argument('entry', default='Main_main_closure', nargs='?')
    arg_parser.add_argument('--ignore-strictness', action='store_true', dest='ignore_strictness')
    arg_parser.add_argument('--apply-functions', action='store_true', dest='apply_functions')
    arg_parser.add_argument('--no-inline-once', action='store_false', dest='inline_once')
    arg_parser.add_argument('--inline-constructors', action='store_true', dest='inline_constructors')
    arg_parser.add_argument('--show-types', action='store_true', dest='show_types')
    arg_parser.add_argument('--no-abbreviate-library-names', action='store_false', dest='abbreviate_library_names')
    arg_parser.add_argument('--verbose', action='store_true', dest='verbose')

    opts = arg_parser.parse_args()
    settings = metadata.read_settings(opts)

    # Parse the binary

    entry_pointer = StaticValue(value = settings.name_to_address[opts.entry])

    interpretations = {}
    run_worklist(settings, interpretations, [ClosureWork(heaps = [], pointer = entry_pointer)])

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
    if opts.inline_constructors:
        optimize.run_inline_constructors(interpretations)
    if opts.apply_functions:
        optimize.run_apply_functions(interpretations)

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

def run_worklist(settings, interps, worklist):
    while len(worklist) > 0:
        work = worklist.pop()
        if isinstance(work, ClosureWork):
            if settings.opts.verbose:
                print("Found closure:")
                print("    Pointer:", show.show_pretty_pointer(settings, work.pointer))

            if isinstance(work.pointer, Argument) or isinstance(work.pointer, CaseArgument) or isinstance(work.pointer, Offset) and isinstance(work.pointer.base, CasePointer):
                if settings.opts.verbose:
                    print("    Simple closure!")
                    print()
                continue

            if isinstance(work.pointer, StaticValue) and show.name_is_library(show.get_name_for_address(settings, work.pointer.value)):
                if settings.opts.verbose:
                    print("    Library defined!")
                    print()
                continue

            interps[work.pointer] = parse.read_closure(settings, worklist, work.heaps, work.pointer)
        elif isinstance(work, FunctionThunkWork):
            if settings.opts.verbose:
                print("Found function/thunk!")
                print("    Name:", show.demangle(show.get_name_for_address(settings, work.address)))
                print("    Arg pattern:", work.arg_pattern)

            if StaticValue(value = work.address) in interps:
                if settings.opts.verbose:
                    print("    Seen before!")
                    print()
                continue

            if show.name_is_library(show.get_name_for_address(settings, work.address)):
                if settings.opts.verbose:
                    print("    Library defined!")
                    print()
                continue

            interps[StaticValue(value = work.address)] = parse.read_function_thunk(settings, worklist, work.heaps, work.address, work.main_register, work.arg_pattern)
        else:
            assert False,"bad work in worklist"

        if settings.opts.verbose:
            print()
