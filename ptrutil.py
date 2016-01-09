import struct

from hstypes import *

def read_half_word(settings, file_offset):
    return struct.unpack(settings.rt.halfword_struct, settings.binary[file_offset:file_offset+settings.rt.halfword_size])[0]

def read_word(settings, file_offset):
    return struct.unpack(settings.rt.word_struct, settings.binary[file_offset:file_offset+settings.rt.word_size])[0]

def pointer_offset(settings, pointer, offset):
    if isinstance(pointer, HeapPointer):
        offset += pointer.tag
        return HeapPointer(heap_segment = pointer.heap_segment, index = pointer.index + offset // settings.rt.word_size, tag = offset % settings.rt.word_size)
    elif isinstance(pointer, StaticValue):
        return StaticValue(value = pointer.value + offset)
    elif isinstance(pointer, StackPointer):
        return StackPointer(index = pointer.index + offset // settings.rt.word_size)
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False,"bad pointer to offset"

def dereference(settings, parsed, pointer, stack):
    if isinstance(pointer, StaticValue):
        assert pointer.value % settings.rt.word_size == 0
        return StaticValue(value = read_word(settings, settings.data_offset + pointer.value))
    elif isinstance(pointer, HeapPointer):
        assert pointer.tag == 0
        return parsed['heaps'][pointer.heap_segment][pointer.index]
    elif isinstance(pointer, StackPointer):
        return stack[pointer.index]
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False, "bad pointer dereference"
