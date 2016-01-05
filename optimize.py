from hstypes import *

def foreach_use(interp, func):
    if isinstance(interp, Apply):
        foreach_use(interp.func, func)
        for arg, pat in zip(interp.args, interp.pattern):
            if pat == 'p':
                foreach_use(arg, func)
    elif isinstance(interp, CaseDefault):
        foreach_use(interp.scrutinee, func)
        foreach_use(interp.arm, func)
    elif isinstance(interp, CaseBool):
        foreach_use(interp.scrutinee, func)
        foreach_use(interp.arm_true, func)
        foreach_use(interp.arm_false, func)
    elif isinstance(interp, StaticValue) or isinstance(interp, HeapPointer) or isinstance(interp, CaseArgument):
        func(interp)

def can_inline(parsed, pointer):
    return pointer in parsed['interpretations'] and not pointer in parsed['num-args']

def is_cheap(parsed, pointer):
    interp = parsed['interpretations'][pointer]
    return isinstance(interp, Argument) or isinstance(interp, CaseArgument) or isinstance(interp, StaticValue) or isinstance(interp, HeapPointer) or (isinstance(interp, Apply) and interp.func_type == 'constructor')

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
    elif isinstance(interp, CaseDefault):
        return CaseDefault(
            scrutinee = run_rewrite(func, interp.scrutinee),
            bound_ptr = interp.bound_ptr,
            arm = run_rewrite(func, interp.arm)
        )
    elif isinstance(interp, CaseBool):
        return CaseBool(
            scrutinee = run_rewrite(func, interp.scrutinee),
            arm_true = run_rewrite(func, interp.arm_true),
            arm_false = run_rewrite(func, interp.arm_false)
        )
    else:
        return interp

def do_inlining(parsed, interp, predicate, inlined):
    if (isinstance(interp, StaticValue) or isinstance(interp, HeapPointer) or isinstance(interp, CaseArgument)) and can_inline(parsed, interp) and predicate(interp):
        inlined.append(interp)
        return parsed['interpretations'][interp]

def destroy_empty_apply(interp):
    if isinstance(interp, Apply) and len(interp.args) == 0:
        return interp.func

def destroy_strictness(interp, new_interps):
    if isinstance(interp, CaseDefault):
        case_argument = CaseArgument(inspection = interp.bound_ptr)
        new_interps.append((case_argument, interp.scrutinee))
        return interp.arm

#####################

def run_destroy_empty_apply(parsed):
    run_rewrite_pass(parsed, destroy_empty_apply)

def run_destroy_strictness(parsed):
    new_interps = []
    run_rewrite_pass(parsed, lambda interp: destroy_strictness(interp, new_interps))
    for lhs, rhs in new_interps:
        parsed['interpretations'][lhs] = rhs

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
