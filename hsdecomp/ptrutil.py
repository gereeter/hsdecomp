import struct

from hsdecomp.types import *

def read_half_word(settings, file_offset):
    return struct.unpack(settings.rt.halfword.struct, settings.binary[file_offset:file_offset+settings.rt.halfword.size])[0]

def read_word(settings, file_offset):
    return struct.unpack(settings.rt.word.struct, settings.binary[file_offset:file_offset+settings.rt.word.size])[0]

def make_tagged(settings, pointer):
    if isinstance(pointer, StaticValue):
        tag = pointer.value % settings.rt.word.size
        return Tagged(untagged = StaticValue(value = pointer.value - tag), tag = tag)
    else:
        return Tagged(untagged = pointer, tag = 0)

def pointer_offset(settings, pointer, offset):
    if isinstance(pointer, Tagged):
        offset += pointer.tag
        if isinstance(pointer.untagged, Offset):
            untagged = Offset(base = pointer.untagged.base, index = pointer.untagged.index + offset // settings.rt.word.size)
        elif isinstance(pointer.untagged, StaticValue):
            untagged = StaticValue(value = pointer.untagged.value + (offset // settings.rt.word.size) * settings.rt.word.size)
        return Tagged(untagged = untagged, tag = offset % settings.rt.word.size)
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False,"bad pointer to offset"

def dereference(settings, pointer, heaps, stack):
    if isinstance(pointer, Offset):
        if isinstance(pointer.base, HeapPointer):
            return heaps[pointer.base.id][pointer.index]
        elif isinstance(pointer.base, StackPointer):
            return stack[pointer.index]
        elif isinstance(pointer.base, CasePointer):
            assert pointer.index > 0
            return Tagged(CaseArgument(inspection = pointer.base.inspection, matched_tag = pointer.base.matched_tag, index = pointer.index - 1), tag = 0)
        else:
            assert False, "bad offset pointer to dereference"
    elif isinstance(pointer, StaticValue):
        assert pointer.value % settings.rt.word.size == 0, "misaligned pointer in dereference"
        return make_tagged(settings, StaticValue(value = read_word(settings, settings.data_offset + pointer.value)))
    else:
        assert False,"bad pointer to dereference"
