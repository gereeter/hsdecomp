import collections

# Settings
Settings = collections.namedtuple('Settings', 'opts rt name_to_address address_to_name binary capstone text_offset data_offset rodata_offset')
Runtime = collections.namedtuple('Runtime', 'halfword word stack_register heap_register main_register arg_registers')
WordDesc = collections.namedtuple('WordDesc', 'size struct')

# Values
HeapPointer = collections.namedtuple('HeapPointer', 'heap_segment index tag')
StackPointer = collections.namedtuple('StackPointer', 'index')
StaticValue = collections.namedtuple('StaticValue', 'value')
UnknownValue = collections.namedtuple('UnknownValue', '')

Argument = collections.namedtuple('Argument', 'func index')
CaseArgument = collections.namedtuple('CaseArgument', 'inspection')

# Interpretations
Pointer = collections.namedtuple('Pointer', 'pointer')
Apply = collections.namedtuple('Apply', 'func func_type args pattern')
Case = collections.namedtuple('Case', 'scrutinee bound_ptr arms tags')

# Tags
Tag = collections.namedtuple('Tag', 'value')
DefaultTag = collections.namedtuple('DefaultTag', '')
