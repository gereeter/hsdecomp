from hsdecomp import show, optimize
from hsdecomp.hstypes import *

bool_type = EnumType(constructor_names = ['False', 'True'])

known_types = {
    'ghczmprim_GHCziClasses_zeze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_znze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zgze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zlze_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zg_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
    'ghczmprim_GHCziClasses_zl_info': FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = FunctionType(arg = UnknownType(), result = bool_type))),
}

def infer_type_for(settings, parsed, pointer):
    if not pointer in parsed['types']:
        if isinstance(pointer, StaticValue) and show.get_name_for_address(settings, pointer.value) in known_types:
            parsed['types'][pointer] = known_types[show.get_name_for_address(settings, pointer.value)]
        else:
            parsed['types'][pointer] = UnknownType()
            if pointer in parsed['interpretations']:
                ty = infer_type(settings, parsed, parsed['interpretations'][pointer])
                if pointer in parsed['num-args']:
                    for i in range(parsed['num-args'][pointer]):
                        ty = FunctionType(arg = UnknownType(), result = ty)
                parsed['types'][pointer] = ty

def infer_type(settings, parsed, interp):
    if isinstance(interp, Apply):
        ty = infer_type(settings, parsed, interp.func)
        for i in range(len(interp.args)):
            if isinstance(ty, FunctionType):
                ty = ty.result
            else:
                assert isinstance(ty, UnknownType)
                break
        return ty
    elif isinstance(interp, Pointer):
        infer_type_for(settings, parsed, interp.pointer)
        return parsed['types'][interp.pointer]
    else:
        return UnknownType()

def run_rename_tags(settings, parsed):
    optimize.run_rewrite_pass(parsed, lambda interp: rename_tags(settings, parsed, interp))

def rename_tags(settings, parsed, interp):
    if isinstance(interp, Case):
        scrut_ty = infer_type(settings, parsed, interp.scrutinee)
        if isinstance(scrut_ty, EnumType):
            seen_tags = {}
            for i in range(len(interp.tags)):
                if isinstance(interp.tags[i], NumericTag):
                    seen_tags[interp.tags[i].value] = None
                    interp.tags[i] = NamedTag(name = scrut_ty.constructor_names[interp.tags[i].value - 1])
            if len(interp.tags) == len(scrut_ty.constructor_names):
                assert len(seen_tags) == len(scrut_ty.constructor_names) - 1
                for i in range(len(interp.tags)):
                    if not i+1 in seen_tags:
                        missing_tag = i
                for i in range(len(interp.tags)):
                    if isinstance(interp.tags[i], DefaultTag):
                        interp.tags[i] = NamedTag(name = scrut_ty.constructor_names[missing_tag])
