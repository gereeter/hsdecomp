import collections

HeapPointer = collections.namedtuple('HeapPointer', 'heap_segment index tag')
StackPointer = collections.namedtuple('StackPointer', 'index')
StaticValue = collections.namedtuple('StaticValue', 'value')
UnknownValue = collections.namedtuple('UnknownValue', '')

Argument = collections.namedtuple('Argument', 'func index')
CaseArgument = collections.namedtuple('CaseArgument', 'value')

Apply = collections.namedtuple('Apply', 'func func_type args pattern')
CaseDefault = collections.namedtuple('CaseDefault', 'scrutinee bound_ptr arm')
CaseBool = collections.namedtuple('CaseBool', 'scrutinee arm_true arm_false')

