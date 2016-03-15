import capstone

def disasm_from_raw(settings, address, num_insns):
    return settings.capstone.disasm(settings.binary[settings.text_offset + address:], address, num_insns)

def disasm_from(settings, address):
    return disasm_from_until(settings, address, lambda insn: insn.mnemonic == 'jmp')

def disasm_from_until(settings, address, predicate):
    while True:
        for insn in disasm_from_raw(settings, address, 20):
            address += insn.size
            yield insn
            if predicate(insn):
                return
