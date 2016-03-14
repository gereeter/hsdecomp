from hsdecomp.types import *

def show_instruction(insn):
    return insn.mnemonic + "\t" + insn.op_str

def get_name_for_address(settings, offset):
    if offset in settings.address_to_name:
        return settings.address_to_name[offset]
    else:
        return "loc_" + str(offset)

def show_pretty_value(settings, value):
    if value == None:
        return "None"
    elif isinstance(value, Tagged):
        return "<" + show_pretty_pointer(settings, value.untagged) + ", tag " + str(value.tag) + ">"
    elif isinstance(value, UnknownValue):
        return "!unknown!"

def show_pretty_address(settings, address):
        name = get_name_for_address(settings, address)
        if settings.opts.abbreviate_library_names and name_is_library(name):
            name = name.split('_')[2]
        return demangle(name)

def show_pretty_pointer(settings, pointer):
    if isinstance(pointer, StaticValue):
        return show_pretty_address(settings, pointer.value)
    elif isinstance(pointer, Offset):
        if isinstance(pointer.base, HeapPointer):
            location = show_pretty_address(settings, pointer.base.owner) + "'s heap"
        elif isinstance(pointer.base, StackPointer):
            location = "the stack"
        elif isinstance(pointer.base, CasePointer):
            location = show_pretty_pointer(settings, pointer.base.inspection) + "_case_tag" + show_pretty_tag(pointer.base.matched_tag)
        return "<index " + str(pointer.index) + " in " + location + ">"
    elif isinstance(pointer, Argument):
        return show_pretty_address(settings, pointer.func) + "_arg_" + str(pointer.index)
    elif isinstance(pointer, CaseArgument):
        return show_pretty_pointer(settings, pointer.inspection) + "_case_tag" + show_pretty_tag(pointer.matched_tag) + "_arg_" + str(pointer.index)
    else:
        assert False, "<<unknown type in show_pretty_pointer: " + str(pointer) + ">>"

def show_pretty_nonptr(settings, value, context):
    if isinstance(context, Pointer) and isinstance(context.pointer, StaticValue) and get_name_for_address(settings, context.pointer.value)[:38] == 'ghczmprim_GHCziCString_unpackCStringzh':
        ret = '"'
        parsed_offset = settings.rodata_offset + value
        while settings.binary[parsed_offset] != 0:
            ret += chr(settings.binary[parsed_offset])
            parsed_offset += 1
        ret += '"'
        return ret
    else:
        return str(value)

def show_pretty_type(settings, ty, wants_parens):
    if isinstance(ty, UnknownType):
        return "?"
    elif isinstance(ty, StateType):
        return "State#"
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
    return '\n'.join(render_pretty_interpretation(settings, interp, 0))

def render_pretty_interpretation(settings, interp, paren_level):
    if isinstance(interp, Apply):
        prec = 1
        func = render_pretty_interpretation(settings, interp.func, 1)
        args = []
        for arg, pat in zip(interp.args, interp.pattern):
            if pat == 'p':
                args.append(render_pretty_interpretation(settings, arg, 2))
            elif pat == 'n':
                args.append([show_pretty_nonptr(settings, arg, interp.func)])
            elif pat == 'v':
                args.append(["state#"])
            else:
                print(pat)
                assert False, "bad argument pattern"

        if len(func) > 1 or any(map(lambda arg: len(arg) > 1, args)):
            ret = func
            for arg in args:
                ret += map(lambda line: "    " + line, arg)
        else:
            ret = [func[0] + ''.join(map(lambda arg: " " + arg[0], args))]
    elif isinstance(interp, Case):
        prec = 0
        scrutinee = render_pretty_interpretation(settings, interp.scrutinee, 0)
        if len(scrutinee) > 1:
            ret = scrutinee
            ret += ["of"]
            ret[0] = "case " + ret[0]
        else:
            ret = ["case " + scrutinee[0] + " of"]

        for arm, tag, idx in zip(interp.arms, interp.tags, range(len(interp.arms))):
            rendered = render_pretty_interpretation(settings, arm, 0)
            rendered[0] = show_pretty_tag(tag) + " -> " + rendered[0]
            if isinstance(tag, DefaultTag):
                rendered[0] = show_pretty_pointer(settings, CaseArgument(inspection = interp.bound_ptr, matched_tag = tag, index = 0)) + "@" + rendered[0]
            if idx < len(interp.arms) - 1:
                rendered[-1] = rendered[-1] + ","

            ret += map(lambda line: "    " + line, rendered)
    elif isinstance(interp, Lambda):
        prec = 0
        body = render_pretty_interpretation(settings, interp.body, 0)
        arg_str = "\\" + " ".join(["state#" if pat == 'v' else show_pretty_pointer(settings, Argument(func = interp.func, index = i)) for i, pat in enumerate(interp.arg_pattern)]) + " ->"
        if len(body) > 1:
            ret = [arg_str] + list(map(lambda line: "    " + line, body))
        else:
            ret = [arg_str + " " + body[0]]
    elif isinstance(interp, Pointer):
        prec = 10
        ret = [show_pretty_pointer(settings, interp.pointer)]
    elif isinstance(interp, UnknownInterpretation):
        prec = 10
        ret = ["!!ERROR!!"]
    else:
        assert False, "Bad interpretation type in show_pretty_interpretation"

    if paren_level > prec:
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
