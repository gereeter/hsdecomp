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
    elif isinstance(interp, Pointer):
        func(interp.pointer)

def can_inline(parsed, pointer):
    return pointer in parsed['interpretations'] and not pointer in parsed['arg-pattern']

def is_cheap(parsed, pointer):
    interp = parsed['interpretations'][pointer]
    return isinstance(interp, Pointer) or (isinstance(interp, Apply) and interp.func_type == 'constructor')

def run_inlining_pass(parsed, predicate):
    inlined = []
    run_rewrite_pass(parsed, lambda interp: do_inlining(parsed, interp, predicate, inlined))
    for pointer in inlined:
        if pointer in parsed['interpretations']:
            del parsed['interpretations'][pointer]

def run_rewrite_pass(parsed, func):
    for pointer in parsed['interpretations']:
        parsed['interpretations'][pointer] = run_rewrite(func, parsed['interpretations'][pointer])

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
    else:
        return interp

def do_inlining(parsed, interp, predicate, inlined):
    if isinstance(interp, Pointer) and can_inline(parsed, interp.pointer) and predicate(interp.pointer):
        inlined.append(interp.pointer)
        return parsed['interpretations'][interp.pointer]

def destroy_empty_apply(interp):
    if isinstance(interp, Apply) and len(interp.pattern) == 0:
        return interp.func

def destroy_strictness(interp, new_interps):
    if isinstance(interp, Case) and len(interp.tags) == 1 and isinstance(interp.tags[0], DefaultTag):
        case_argument = Offset(base = CaseArgument(inspection = interp.bound_ptr, matched_tag = interp.tags[0]), index = 0)
        new_interps.append((case_argument, interp.scrutinee))
        return interp.arms[0]

#####################

def run_destroy_empty_apply(parsed):
    run_rewrite_pass(parsed, destroy_empty_apply)

def run_destroy_strictness(parsed):
    new_interps = []
    run_rewrite_pass(parsed, lambda interp: destroy_strictness(interp, new_interps))
    for lhs, rhs in new_interps:
        parsed['interpretations'][lhs] = rhs

def run_delete_unused(parsed, entry_pointer):
    worklist = [entry_pointer]
    saved_interps = {}
    while len(worklist) > 0:
        pointer = worklist.pop()
        if pointer in saved_interps or not pointer in parsed['interpretations']:
            continue

        interp = parsed['interpretations'][pointer]
        saved_interps[pointer] = interp
        foreach_use(interp, lambda ptr: worklist.append(ptr))
    parsed['interpretations'] = saved_interps

def run_inline_once(parsed):
    uses = {}

    def add_use(interp):
        if interp in uses:
            uses[interp] += 1

    for pointer in parsed['interpretations']:
        uses[pointer] = 0
    for pointer in parsed['interpretations']:
        foreach_use(parsed['interpretations'][pointer], add_use)

    run_inlining_pass(parsed, lambda sp: uses[sp] == 1)

def run_inline_cheap(parsed):
    run_inlining_pass(parsed, lambda sp: is_cheap(parsed, sp))
