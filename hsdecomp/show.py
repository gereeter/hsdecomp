from hsdecomp.types import *

def show_instruction(insn):
    return insn.mnemonic + "\t" + insn.op_str

def get_name_for_address(settings, offset):
    if offset in settings.address_to_name:
        return settings.address_to_name[offset]
    else:
        return "loc_" + str(offset)

def show_pretty(settings, pointer):
    try:
        if pointer == None:
            return "None"
        elif isinstance(pointer, StaticValue):
            name = get_name_for_address(settings, pointer.value)
            if settings.opts.abbreviate_library_names and name_is_library(name):
                name = name.split('_')[2]
            return demangle(name)
        elif isinstance(pointer, HeapPointer):
            return "<index " + str(pointer.index) + " in " + show_pretty(settings, pointer.heap_segment) + "'s heap, tag " + str(pointer.tag) + ">"
        elif isinstance(pointer, Argument):
            return demangle(pointer.func) + "_arg_" + str(pointer.index)
        elif isinstance(pointer, CaseArgument):
            return show_pretty(settings, pointer.inspection) + "_case_input"
        elif isinstance(pointer, UnknownValue):
            return "!unknown!"
        else:
            return "<<unknown type in show_pretty: " + str(pointer) + ">>"
    except:
        return ("<<Error in show_pretty, pointer = " + str(pointer) + ">>")

def show_pretty_nonptr(settings, value, context):
    assert isinstance(value, StaticValue)
    if isinstance(context, Pointer) and isinstance(context.pointer, StaticValue) and get_name_for_address(settings, context.pointer.value) == 'ghczmprim_GHCziCString_unpackCStringzh_closure':
        ret = '"'
        parsed_offset = settings.rodata_offset + value.value
        while settings.binary[parsed_offset] != 0:
            ret += chr(settings.binary[parsed_offset])
            parsed_offset += 1
        ret += '"'
        return ret
    else:
        return str(value.value)

def show_pretty_type(settings, ty, wants_parens):
    if isinstance(ty, UnknownType):
        return "?"
    elif isinstance(ty, FunctionType):
        ret = show_pretty_type(settings, ty.arg, True) + " -> " + show_pretty_type(settings, ty.result, False)
        if wants_parens:
            ret = "(" + ret + ")"
        return ret
    elif isinstance(ty, EnumType):
        return "|".join(ty.constructor_names)

def show_pretty_tag(tag):
    if isinstance(tag, NumericTag):
        return "<tag " + str(tag.value) + ">"
    elif isinstance(tag, NamedTag):
        return demangle(tag.name)
    elif isinstance(tag, DefaultTag):
        return "_DEFAULT"
    else:
        assert False, "Bad tag type"

def show_pretty_interpretation(settings, interp):
    return '\n'.join(render_pretty_interpretation(settings, interp, False))

def render_pretty_interpretation(settings, interp, wants_parens):
    if isinstance(interp, Apply):
        func = render_pretty_interpretation(settings, interp.func, False)
        args = []
        for arg, pat in zip(interp.args, interp.pattern):
            if pat == 'p':
                args.append(render_pretty_interpretation(settings, arg, True))
            elif pat == 'n':
                args.append([show_pretty_nonptr(settings, arg.pointer, interp.func)])
            else:
                assert False, "bad argument pattern"

        if len(func) > 1 or any(map(lambda arg: len(arg) > 1, args)):
            ret = func
            for arg in args:
                ret += map(lambda line: "    " + line, arg)
        else:
            ret = [func[0] + ''.join(map(lambda arg: " " + arg[0], args))]
    elif isinstance(interp, Case):
        scrutinee = render_pretty_interpretation(settings, interp.scrutinee, False)
        if len(scrutinee) > 1:
            ret = scrutinee
            ret += ["of"]
            ret[0] = "case " + ret[0]
        else:
            ret = ["case " + scrutinee[0] + " of"]

        for arm, tag, idx in zip(interp.arms, interp.tags, range(len(interp.arms))):
            rendered = render_pretty_interpretation(settings, arm, False)
            rendered[0] = show_pretty_tag(tag) + " -> " + rendered[0]
            if isinstance(tag, DefaultTag):
                rendered[0] = show_pretty(settings, CaseArgument(inspection = interp.bound_ptr)) + "@" + rendered[0]
            if idx < len(interp.arms) - 1:
                rendered[-1] = rendered[-1] + ","

            ret += map(lambda line: "    " + line, rendered)
    elif isinstance(interp, Pointer):
        return [show_pretty(settings, interp.pointer)]
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
