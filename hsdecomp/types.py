import collections

# Settings
Settings = collections.namedtuple('Settings', 'opts version rt name_to_address address_to_name binary capstone text_offset data_offset rodata_offset')
Runtime = collections.namedtuple('Runtime', 'halfword word stack_register heap_register main_register arg_registers')
WordDesc = collections.namedtuple('WordDesc', 'size lg_size struct')

# Values
Offset = collections.namedtuple('Offset', 'base index tag')

HeapPointer = collections.namedtuple('HeapPointer', 'heap_segment')
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
NamedTag = collections.namedtuple('NamedTag', 'name')
NumericTag = collections.namedtuple('NumericTag', 'value')
DefaultTag = collections.namedtuple('DefaultTag', '')

# Types
UnknownType = collections.namedtuple('UnknownType', '')
StateType = collections.namedtuple('StateType', '')
FunctionType = collections.namedtuple('FunctionType', 'arg result')
EnumType = collections.namedtuple('EnumType', 'constructor_names complete')
