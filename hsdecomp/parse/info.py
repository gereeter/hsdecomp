import struct

from hsdecomp import ptrutil

def read_arg_pattern(settings, address):
    num_args = read_num_args(settings, address)
    func_type = read_function_type(settings, address)
    assert num_args >= len(func_type)
    return func_type + 'v' * (num_args - len(func_type))

def read_num_args(settings, address):
    return ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*5)

def read_function_type(settings, address):
    type_table = {
        3: '',
        4: 'n',
        5: 'p',
        12: 'nn',
        13: 'np',
        14: 'pn',
        15: 'pp',
        16: 'nnn',
        17: 'nnp',
        18: 'npn',
        19: 'npp',
        20: 'pnn',
        21: 'pnp',
        22: 'ppn',
        23: 'ppp',
        24: 'pppp',
        25: 'ppppp',
        26: 'pppppp',
        27: 'ppppppp',
        28: 'pppppppp'
    }
    type = ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*6)
    if type >= 12 and settings.version < (7, 8, 0):
        # Introduction of vector arguments
        type += 3
    if type in type_table:
        return type_table[type]
    elif type == 0:
        bitmap = ptrutil.read_word(settings, settings.text_offset + address - settings.rt.word.size*5)
        size = bitmap & (settings.word.size - 1)
        bits = bitmap >> settings.word.lg_size
        ret = ''
        for i in range(size):
            if bits % 2 == 0:
                ret += 'p'
            else:
                ret += 'n'
            bits //= 2
        return ret
    else:
       # TODO: Read large bitmaps
       assert False, "unknown function type"

def read_closure_type(settings, address):
    type_table = {
        1: 'constructor',
        2: 'constructor (1 ptr, 0 nonptr)',
        3: 'constructor (0 ptr, 1 nonptr)',
        4: 'constructor (2 ptr, 0 nonptr)',
        5: 'constructor (1 ptr, 1 nonptr)',
        6: 'constructor (0 ptr, 2 nonptr)',
        7: 'constructor (static)',
        8: 'constructor (no CAF, static)',
        9: 'function',
        10: 'function (1 ptr, 0 nonptr)',
        11: 'function (0 ptr, 1 nonptr)',
        12: 'function (2 ptr, 0 nonptr)',
        13: 'function (1 ptr, 1 nonptr)',
        14: 'function (0 ptr, 2 nonptr)',
        15: 'function (static)',
        16: 'thunk',
        17: 'thunk (1 ptr, 0 nonptr)',
        18: 'thunk (0 ptr, 1 nonptr)',
        19: 'thunk (2 ptr, 0 nonptr)',
        20: 'thunk (1 ptr, 1 nonptr)',
        21: 'thunk (0 ptr, 2 nonptr)',
        22: 'thunk (static)',
        23: 'selector',
        28: 'indirection',
        29: 'indirection (permanent)',
        30: 'indirection (static)'
    }
    type = ptrutil.read_half_word(settings, settings.text_offset + address - settings.rt.halfword.size*2)
    if type in type_table:
        return type_table[type]
    else:
        return 'unknown: ' + str(type)
