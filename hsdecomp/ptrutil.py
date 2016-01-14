import struct

from hsdecomp.types import *

def read_half_word(settings, file_offset):
    return struct.unpack(settings.rt.halfword.struct, settings.binary[file_offset:file_offset+settings.rt.halfword.size])[0]

def read_word(settings, file_offset):
    return struct.unpack(settings.rt.word.struct, settings.binary[file_offset:file_offset+settings.rt.word.size])[0]

def pointer_offset(settings, pointer, offset):
    if isinstance(pointer, Tagged):
        offset += pointer.tag
        assert isinstance(pointer.base, Offset)
        return Tagged(base = Offset(base = pointer.base.base, index = pointer.base.index + offset // settings.rt.word.size), tag = offset % settings.rt.word.size)
    elif isinstance(pointer, StaticValue):
        return StaticValue(value = pointer.value + offset)
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False,"bad pointer to offset"

def retag(settings, pointer, tag):
    if isinstance(pointer, Tagged):
        return pointer._replace(tag = tag)
    elif isinstance(pointer, StaticValue):
        tagmask = settings.rt.word.size - 1
        cleared = pointer.value & ~tagmask
        return StaticValue(value = cleared | tag)
    elif isinstance(pointer, CaseArgument) or isinstance(pointer, Argument):
        assert tag == 0
        return pointer
    else:
        assert False,"bad pointer to retag"

def dereference(settings, parsed, pointer, stack):
    if isinstance(pointer, StaticValue):
        assert pointer.value % settings.rt.word.size == 0
        return StaticValue(value = read_word(settings, settings.data_offset + pointer.value))
    elif isinstance(pointer, Tagged):
        assert pointer.tag == 0
        assert isinstance(pointer.base, Offset)
        if isinstance(pointer.base.base, HeapPointer):
            return parsed['heaps'][pointer.base.base.heap_segment][pointer.base.index]
        elif isinstance(pointer.base.base, StackPointer):
            return stack[pointer.base.index]
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False, "bad pointer dereference"
