from hsdecomp.types import *

def foreach_use(interp, func):
    if isinstance(interp, Apply):
        foreach_use(interp.func, func)
        for arg, pat in zip(interp.args, interp.pattern):
            if pat == 'p':
                foreach_use(arg, func)
    elif isinstance(interp, Case):
        foreach_use(interp.scrutinee, func)
        for arm in interp.arms:
            foreach_use(arm, func)
    elif isinstance(interp, Lambda):
        foreach_use(interp.body, func)
    elif isinstance(interp, Pointer):
        func(interp.pointer)

def can_inline(interpretations, pointer):
    return pointer in interpretations

def is_basic_constructor(interpretations, pointer):
    print(pointer)
    interp = interpretations[pointer]
    print(interp)
    return isinstance(interp, Apply) and interp.func_type == 'constructor' and 'p' not in interp.pattern

def run_inlining_pass(interpretations, predicate):
    inlined = []
    run_rewrite_pass(interpretations, lambda interp: do_inlining(interpretations, interp, predicate, inlined))
    for pointer in inlined:
        if pointer in interpretations:
            del interpretations[pointer]

def run_rewrite_pass(interpretations, func):
    for pointer in interpretations:
        interpretations[pointer] = run_rewrite(func, interpretations[pointer])

def run_rewrite(func, interp):
    while True:
        trans = func(interp)
        if trans == None:
            break
        else:
            interp = trans

    if isinstance(interp, Apply):
        new_args = []
        for arg, pat in zip(interp.args, interp.pattern):
            if pat == 'p':
                new_args.append(run_rewrite(func, arg))
            else:
                new_args.append(arg)
        return Apply(
            func_type = interp.func_type,
            func = run_rewrite(func, interp.func),
            args = new_args,
            pattern = interp.pattern
        )
    elif isinstance(interp, Case):
        return Case(
            scrutinee = run_rewrite(func, interp.scrutinee),
            bound_ptr = interp.bound_ptr,
            arms = list(map(lambda arm: run_rewrite(func, arm), interp.arms)),
            tags = interp.tags
        )
    elif isinstance(interp, Lambda):
        return Lambda(
            func = interp.func,
            arg_pattern = interp.arg_pattern,
            body = run_rewrite(func, interp.body)
        )
    else:
        return interp

def do_inlining(interpretations, interp, predicate, inlined):
    if isinstance(interp, Pointer) and can_inline(interpretations, interp.pointer) and predicate(interp.pointer):
        inlined.append(interp.pointer)
        return interpretations[interp.pointer]

def destroy_empty_apply(interp):
    if isinstance(interp, Apply) and len(interp.pattern) == 0:
        return interp.func

def destroy_strictness(interp, new_interps):
    if isinstance(interp, Case) and len(interp.tags) == 1 and isinstance(interp.tags[0], DefaultTag):
        case_argument = Offset(base = CasePointer(inspection = interp.bound_ptr, matched_tag = interp.tags[0]), index = 0)
        new_interps.append((case_argument, interp.scrutinee))
        return interp.arms[0]

def apply_functions(substs, interp):
    if isinstance(interp, Pointer) and interp.pointer in substs:
        return substs[interp.pointer]
    elif isinstance(interp, Apply) and isinstance(interp.func, Lambda):
        for i, arg in enumerate(interp.args[:len(interp.func.arg_pattern)]):
            substs[Argument(func = interp.func.func, index = i)] = arg
        if len(interp.pattern) > len(interp.func.arg_pattern):
            return Apply(
                func_type = interp.func_type,
                func = interp.func.body,
                args = interp.args[len(interp.func.arg_pattern):],
                pattern = interp.pattern[len(interp.func.arg_pattern):]
            )
        elif len(interp.pattern) < len(interp.func.arg_pattern):
            return Lambda(
                func = interp.func.func,
                arg_pattern = interp.func.arg_pattern[len(interp.pattern):],
                body = interp.func.body
            )
        else:
            return interp.func.body

#####################

def run_apply_functions(interpretations):
    substitutions = {}
    run_rewrite_pass(interpretations, lambda interp: apply_functions(substitutions, interp))

def run_destroy_empty_apply(interpretations):
    run_rewrite_pass(interpretations, destroy_empty_apply)

def run_destroy_strictness(interpretations):
    new_interps = []
    run_rewrite_pass(interpretations, lambda interp: destroy_strictness(interp, new_interps))
    for lhs, rhs in new_interps:
        interpretations[lhs] = rhs

def run_delete_unused(interpretations, entry_pointer):
    worklist = [entry_pointer]
    saved_interps = {}
    while len(worklist) > 0:
        pointer = worklist.pop()
        if pointer in saved_interps or not pointer in interpretations:
            continue

        interp = interpretations[pointer]
        saved_interps[pointer] = interp
        foreach_use(interp, lambda ptr: worklist.append(ptr))
    return saved_interps

def run_inline_once(interpretations):
    uses = {}

    def add_use(interp):
        if interp in uses:
            uses[interp] += 1

    for pointer in interpretations:
        uses[pointer] = 0
    for pointer in interpretations:
        foreach_use(interpretations[pointer], add_use)

    run_inlining_pass(interpretations, lambda sp: uses[sp] == 1)

def run_inline_cheap(interpretations):
    run_inlining_pass(interpretations, lambda sp: isinstance(interpretations[sp], Pointer))

def run_inline_constructors(interpretations):
    run_inlining_pass(interpretations, lambda sp: is_basic_constructor(interpretations, sp))
