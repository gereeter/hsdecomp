import struct

from hsdecomp.types import *

def read_half_word(settings, file_offset):
    return struct.unpack(settings.rt.halfword.struct, settings.binary[file_offset:file_offset+settings.rt.halfword.size])[0]

def read_word(settings, file_offset):
    return struct.unpack(settings.rt.word.struct, settings.binary[file_offset:file_offset+settings.rt.word.size])[0]

def pointer_offset(settings, pointer, offset):
    if isinstance(pointer, Tagged):
        offset += pointer.tag
        assert isinstance(pointer.untagged, Offset)
        return Tagged(untagged = Offset(base = pointer.untagged.base, index = pointer.untagged.index + offset // settings.rt.word.size), tag = offset % settings.rt.word.size)
    elif isinstance(pointer, StaticValue):
        return StaticValue(value = pointer.value + offset)
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False,"bad pointer to offset"

def detag(settings, pointer):
    if isinstance(pointer, Tagged):
        return pointer.untagged
    else:
        return retag(settings, pointer, 0)

def dereference(settings, parsed, pointer, stack):
    if isinstance(pointer, Offset):
        if isinstance(pointer.base, HeapPointer):
            return parsed['heaps'][pointer.base.heap_segment][pointer.index]
        elif isinstance(pointer.base, StackPointer):
            return stack[pointer.index]
    elif isinstance(pointer, StaticValue):
        assert pointer.value % settings.rt.word.size == 0
        return Tagged(StaticValue(value = read_word(settings, settings.data_offset + pointer.value)), tag = 0)
