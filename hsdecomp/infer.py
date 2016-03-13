from hsdecomp import show, optimize
from hsdecomp.types import *

bool_type = EnumType(constructor_names = {1: 'False', 2: 'True'}, complete = True)

known_types = {
    'ghczmprim_GHCziClasses_zeze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_znze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zgze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zlze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zg_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zl_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
}

def infer_type_for(settings, interps, types, pointer):
    if not pointer in types:
        if isinstance(pointer, StaticValue) and show.get_name_for_address(settings, pointer.value) in known_types:
            types[pointer] = known_types[show.get_name_for_address(settings, pointer.value)]
        else:
            types[pointer] = UnknownType()
            if pointer in interps:
                types[pointer] = infer_type(settings, interps, types, interps[pointer])

def infer_type(settings, interps, types, interp):
    if isinstance(interp, Apply):
        ty = infer_type(settings, interps, types, interp.func)
        for i in range(len(interp.pattern)):
            if isinstance(ty, FunctionType):
                ty = ty.result
            else:
                assert isinstance(ty, UnknownType)
                break
        return ty
    elif isinstance(interp, Lambda):
        ty = infer_type(settings, interps, types, interp.body)
        for pat in interp.arg_pattern:
            if pat == 'v':
                arg_ty = StateType()
            else:
                arg_ty = UnknownType()
            ty = FunctionType(arg = arg_ty, result = ty)
        return ty
    elif isinstance(interp, Pointer):
        infer_type_for(settings, interps, types, interp.pointer)
        return types[interp.pointer]
    else:
        return UnknownType()

def run_rename_tags(settings, interps, types):
    optimize.run_rewrite_pass(interps, lambda interp: rename_tags(settings, interps, types, interp))

def rename_tags(settings, interps, types, interp):
    if isinstance(interp, Case):
        scrut_ty = infer_type(settings, interps, types, interp.scrutinee)
        if isinstance(scrut_ty, EnumType):
            seen_tags = {}
            for i in range(len(interp.tags)):
                tag = interp.tags[i]
                if isinstance(tag, NumericTag):
                    seen_tags[tag.value] = None
                    interp.tags[i] = NamedTag(name = scrut_ty.constructor_names[tag.value], value = tag.value)
            if scrut_ty.complete and len(interp.tags) == len(scrut_ty.constructor_names):
                assert len(seen_tags) == len(scrut_ty.constructor_names) - 1
                for i in range(len(interp.tags)):
                    if not i+1 in seen_tags:
                        missing_tag = i+1
                        break
                for i in range(len(interp.tags)):
                    if isinstance(interp.tags[i], DefaultTag):
                        interp.tags[i] = NamedTag(name = scrut_ty.constructor_names[missing_tag], value = missing_tag)
