from hstypes import *

def show_instruction(insn):
    return insn.mnemonic + "\t" + insn.op_str

def get_name_for_address(parsed, offset):
    if offset in parsed['address-to-name']:
        return parsed['address-to-name'][offset]
    else:
        return "loc_" + str(offset)

def show_pretty(parsed, pointer):
    try:
        if pointer == None:
            return "None"
        elif isinstance(pointer, StaticValue):
            name = get_name_for_address(parsed, pointer.value)
            if parsed['opts'].abbreviate_library_names and name_is_library(name):
                name = name.split('_')[2]
            return demangle(name)
        elif isinstance(pointer, HeapPointer):
            return "<index " + str(pointer.index) + " in " + show_pretty(parsed, pointer.heap_segment) + "'s heap, tag " + str(pointer.tag) + ">"
        elif isinstance(pointer, Argument):
            return demangle(pointer.func) + "_arg_" + str(pointer.index)
        elif isinstance(pointer, CaseArgument):
            return show_pretty(parsed, pointer.inspection) + "_case_input"
        elif isinstance(pointer, UnknownValue):
            return "!unknown!"
        else:
            return "<<unknown type in show_pretty: " + str(pointer) + ">>"
    except:
        return ("<<Error in show_pretty, pointer = " + str(pointer) + ">>")

def show_pretty_nonptr(parsed, value, context):
    assert isinstance(value, StaticValue)
    if isinstance(context, StaticValue) and get_name_for_address(parsed, context.value) == 'ghczmprim_GHCziCString_unpackCStringzh_closure':
        ret = '"'
        parsed_offset = parsed['rodata-offset'] + value.value
        while parsed['binary'][parsed_offset] != 0:
            ret += chr(parsed['binary'][parsed_offset])
            parsed_offset += 1
        ret += '"'
        return ret
    else:
        return str(value.value)

def show_pretty_interpretation(parsed, interp):
    return '\n'.join(render_pretty_interpretation(parsed, interp, False))

def render_pretty_interpretation(parsed, interp, wants_parens):
    if isinstance(interp, Apply):
        func = render_pretty_interpretation(parsed, interp.func, False)
        args = []
        for arg, pat in zip(interp.args, interp.pattern):
            if pat == 'p':
                args.append(render_pretty_interpretation(parsed, arg, True))
            elif pat == 'n':
                args.append([show_pretty_nonptr(parsed, arg.pointer, interp.func)])
            else:
                assert False, "bad argument pattern"

        if len(func) > 1 or any(map(lambda arg: len(arg) > 1, args)):
            ret = func
            for arg in args:
                ret += map(lambda line: "    " + line, arg)
        else:
            ret = [func[0] + ''.join(map(lambda arg: " " + arg[0], args))]
    elif isinstance(interp, CaseDefault):
        scrutinee = render_pretty_interpretation(parsed, interp.scrutinee, False)
        if len(scrutinee) > 1:
            ret = scrutinee
            ret += ["of"]
            ret[0] = "case " + ret[0]
        else:
            ret = ["case " + scrutinee[0] + " of"]

        arm = render_pretty_interpretation(parsed, interp.arm, False)
        arm[0] = show_pretty(parsed, CaseArgument(inspection = interp.bound_ptr)) + "@_DEFAULT -> " + arm[0]

        ret += map(lambda line: "    " + line, arm)
    elif isinstance(interp, CaseBool):
        scrutinee = render_pretty_interpretation(parsed, interp.scrutinee, False)
        if len(scrutinee) > 1:
            ret = scrutinee
            ret += ["of"]
            ret[0] = "case " + ret[0]
        else:
            ret = ["case " + scrutinee[0] + " of"]
        arm_true = render_pretty_interpretation(parsed, interp.arm_true, False)
        arm_false = render_pretty_interpretation(parsed, interp.arm_false, False)

        arm_true[0] = "True -> " + arm_true[0]
        arm_true[-1] = arm_true[-1] + ","
        arm_false[0] = "False -> " + arm_false[0]

        ret += map(lambda line: "    " + line, arm_true)
        ret += map(lambda line: "    " + line, arm_false)
    elif isinstance(interp, Pointer):
        return [show_pretty(parsed, interp.pointer)]
    else:
        assert False, "Bad interpretation type in show_pretty_interpretation"

    if wants_parens:
        if len(ret) > 1:
            ret[0] = "(" + ret[0]
            ret.append(")")
        else:
            ret = ["(" + ret[0] + ")"]

    return ret

def demangle(ident):
    table = {'L': '(', 'R': ')', 'M': '[', 'N': ']', 'C': ':', 'Z': 'Z', 'a': '&', 'b': '|', 'c': '^', 'd': '$', 'e': '=', 'g': '>', 'h': '#', 'i': '.', 'l': '<', 'm': '-', 'n': '!', 'p': '+', 'q': '\'', 'r': '\\', 's': '/', 't': '*', 'v': '%', 'z': 'z'}
    out = ""
    i = 0
    while i < len(ident):
        if ident[i] == 'z' or ident[i] == 'Z':
            if ident[i+1] in table:
                out += table[ident[i+1]]
                i += 2
                continue
        out += ident[i]
        i += 1
    return out

def name_is_library(name):
    parts = name.split('_')
    return len(parts) >= 4 and (parts[-1] == 'info' or parts[-1] == 'closure')
