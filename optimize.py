import ser

def foreach_use(interp, func):
    if interp['type'] == 'apply':
        foreach_use(interp['func'], func)
        for arg, pat in zip(interp['args'], interp['pattern']):
            if pat == 'p':
                foreach_use(arg, func)
    elif interp['type'] == 'case-default':
        foreach_use(interp['scrutinee'], func)
        foreach_use(interp['arm'], func)
    elif interp['type'] == 'case-bool':
        foreach_use(interp['scrutinee'], func)
        foreach_use(interp['arm-true'], func)
        foreach_use(interp['arm-false'], func)
    elif interp['type'] == 'static' or interp['type'] == 'dynamic' or interp['type'] == 'case-argument':
        func(interp)

def can_inline(parsed, ser_ptr):
    return ser_ptr in parsed['interpretations'] and not ser_ptr in parsed['num-args']

def is_cheap(parsed, ser_ptr):
    interp = parsed['interpretations'][ser_ptr]
    return interp['type'] == 'argument' or interp['type'] == 'case-argument' or interp['type'] == 'static' or interp['type'] == 'dynamic' or (interp['type'] == 'apply' and interp['func-type'] == 'constructor')

def run_inlining_pass(parsed, predicate):
    inlined = []
    run_rewrite_pass(parsed, lambda interp: do_inlining(parsed, interp, predicate, inlined))
    for ser_ptr in inlined:
        if ser_ptr in parsed['interpretations']:
            del parsed['interpretations'][ser_ptr]

def run_rewrite_pass(parsed, func):
    for ser_ptr in parsed['interpretations']:
        parsed['interpretations'][ser_ptr] = run_rewrite(func, parsed['interpretations'][ser_ptr])

def run_rewrite(func, interp):
    while True:
        trans = func(interp)
        if trans == None:
            break
        else:
            interp = trans

    if interp['type'] == 'apply':
        new_args = []
        for arg, pat in zip(interp['args'], interp['pattern']):
            if pat == 'p':
                new_args.append(run_rewrite(func, arg))
            else:
                new_args.append(arg)
        return {
            'type': 'apply',
            'func-type': interp['func-type'],
            'func': run_rewrite(func, interp['func']),
            'args': new_args,
            'pattern': interp['pattern']
        }
    elif interp['type'] == 'case-default':
        return {
            'type': 'case-default',
            'scrutinee': run_rewrite(func, interp['scrutinee']),
            'bound-name': interp['bound-name'],
            'arm': run_rewrite(func, interp['arm'])
        }
    elif interp['type'] == 'case-bool':
        return {
            'type': 'case-bool',
            'scrutinee': run_rewrite(func, interp['scrutinee']),
            'arm-true': run_rewrite(func, interp['arm-true']),
            'arm-false': run_rewrite(func, interp['arm-false'])
        }
    else:
        return interp

def do_inlining(parsed, interp, predicate, inlined):
    if (interp['type'] == 'static' or interp['type'] == 'dynamic' or interp['type'] == 'case-argument') and can_inline(parsed, ser.serialize(interp)) and predicate(ser.serialize(interp)):
        inlined.append(ser.serialize(interp))
        return parsed['interpretations'][ser.serialize(interp)]

def destroy_empty_apply(interp):
    if interp['type'] == 'apply' and len(interp['args']) == 0:
        return interp['func']

def destroy_strictness(interp, new_interps):
    if interp['type'] == 'case-default':
        case_argument = {'type': 'case-argument', 'value': interp['bound-name']}
        new_interps.append((case_argument, interp['scrutinee']))
        return interp['arm']

#####################

def run_destroy_empty_apply(parsed):
    run_rewrite_pass(parsed, destroy_empty_apply)

def run_destroy_strictness(parsed):
    new_interps = []
    run_rewrite_pass(parsed, lambda interp: destroy_strictness(interp, new_interps))
    for lhs, rhs in new_interps:
        parsed['interpretations'][ser.serialize(lhs)] = rhs

def run_inline_once(parsed):
    uses = {}

    def add_use(interp):
        if ser.serialize(interp) in uses:
            uses[ser.serialize(interp)] += 1

    for ser_ptr in parsed['interpretations']:
        uses[ser_ptr] = 0
    for ser_ptr in parsed['interpretations']:
        foreach_use(parsed['interpretations'][ser_ptr], add_use)

    run_inlining_pass(parsed, lambda sp: uses[sp] == 1)

def run_inline_cheap(parsed):
    run_inlining_pass(parsed, lambda sp: is_cheap(parsed, sp))
