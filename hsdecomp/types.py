import collections

# Settings
Settings = collections.namedtuple('Settings', 'opts version rt name_to_address address_to_name binary capstone text_offset data_offset rodata_offset')
Runtime = collections.namedtuple('Runtime', 'halfword word stack_register heap_register main_register arg_registers')
WordDesc = collections.namedtuple('WordDesc', 'size lg_size struct')

# Machine Values
Tagged = collections.namedtuple('Tagged', 'untagged tag')
UnknownValue = collections.namedtuple('UnknownValue', '')

# Pointers

Offset = collections.namedtuple('Offset', 'base index')
StaticValue = collections.namedtuple('StaticValue', 'value')
Argument = collections.namedtuple('Argument', 'func index')
CaseArgument = collections.namedtuple('CaseArgument', 'inspection matched_tag index')

HeapPointer = collections.namedtuple('HeapPointer', 'id owner')
StackPointer = collections.namedtuple('StackPointer', '')
CasePointer = collections.namedtuple('CasePointer', 'inspection matched_tag')

# Interpretations
Pointer = collections.namedtuple('Pointer', 'pointer')
Apply = collections.namedtuple('Apply', 'func func_type args pattern')
Case = collections.namedtuple('Case', 'scrutinee bound_ptr arms tags')
Lambda = collections.namedtuple('Lambda', 'func arg_pattern body')
UnknownInterpretation = collections.namedtuple('UnknownInterpretation', '')

# Tags
NamedTag = collections.namedtuple('NamedTag', 'name value')
NumericTag = collections.namedtuple('NumericTag', 'value')
DefaultTag = collections.namedtuple('DefaultTag', '')

# Types
UnknownType = collections.namedtuple('UnknownType', '')
StateType = collections.namedtuple('StateType', '')
FunctionType = collections.namedtuple('FunctionType', 'arg result')
EnumType = collections.namedtuple('EnumType', 'constructor_names complete')

# Work
ClosureWork = collections.namedtuple('ClosureWork', 'heaps pointer')
FunctionThunkWork = collections.namedtuple('FunctionThunkWork', 'heaps address main_register arg_pattern')
