import struct

from hstypes import *

def read_half_word(parsed, file_offset):
    return struct.unpack(parsed['halfword-struct'], parsed['binary'][file_offset:file_offset+parsed['halfword-size']])[0]

def read_word(parsed, file_offset):
    return struct.unpack(parsed['word-struct'], parsed['binary'][file_offset:file_offset+parsed['word-size']])[0]

def pointer_offset(parsed, pointer, offset):
    if isinstance(pointer, HeapPointer):
        offset += pointer.tag
        return HeapPointer(heap_segment = pointer.heap_segment, index = pointer.index + offset // parsed['word-size'], tag = offset % parsed['word-size'])
    elif isinstance(pointer, StaticValue):
        return StaticValue(value = pointer.value + offset)
    elif isinstance(pointer, StackPointer):
        return StackPointer(index = pointer.index + offset // parsed['word-size'])
    else:
        assert False,"bad pointer to offset"

def dereference(parsed, pointer, stack):
    if isinstance(pointer, StaticValue):
        assert pointer.value % parsed['word-size'] == 0
        return StaticValue(value = read_word(parsed, parsed['data-offset'] + pointer.value))
    elif isinstance(pointer, HeapPointer):
        assert pointer.tag == 0
        return parsed['heaps'][pointer.heap_segment][pointer.index]
    elif isinstance(pointer, StackPointer):
        return stack[pointer.index]
    elif isinstance(pointer, UnknownValue):
        return UnknownValue()
    else:
        assert False, "bad pointer dereference"
