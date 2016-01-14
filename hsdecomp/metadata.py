import capstone
from elftools.elf.elffile import ELFFile

from hsdecomp.parse import disasm
from hsdecomp.types import *

def read_version(settings):
    if 'printRtsInfo' in settings.name_to_address:
        for insn in disasm.disasm_from_until(settings, settings.name_to_address['printRtsInfo'], lambda insn: insn.group(capstone.x86.X86_GRP_RET)):
            if insn.mnemonic == 'mov' and insn.operands[1].type == capstone.x86.X86_OP_IMM:
                str_start = settings.rodata_offset + insn.operands[1].imm
                if b'\0' in settings.binary[str_start:str_start+20]:
                    str_len = settings.binary[str_start:str_start+20].index(b'\0')
                    ver_str = settings.binary[str_start:str_start+str_len]
                    parts = ver_str.split(b'.')
                    if len(parts) == 3 and all(map(lambda part: part.isdigit(), parts)):
                        return (int(parts[0]), int(parts[1]), int(parts[2]))

def read_settings(opts):
    elffile = ELFFile(open(opts.file, "rb"))

    if elffile.elfclass == 32:
        capstone_mode = capstone.CS_MODE_32
        runtime = Runtime(
            halfword = WordDesc(size = 2, lg_size = 1, struct = '<H'),
            word = WordDesc(size = 4, lg_size = 2, struct = '<I'),
            stack_register = capstone.x86.X86_REG_RBP,
            heap_register = capstone.x86.X86_REG_RDI,
            main_register = capstone.x86.X86_REG_RSI,
            arg_registers = []
        )
    elif elffile.elfclass == 64:
        capstone_mode = capstone.CS_MODE_64
        runtime = Runtime(
            halfword = WordDesc(size = 4, lg_size = 2, struct = '<I'),
            word = WordDesc(size = 8, lg_size = 3, struct = '<Q'),
            stack_register = capstone.x86.X86_REG_RBP,
            heap_register = capstone.x86.X86_REG_R12,
            main_register = capstone.x86.X86_REG_RBX,
            arg_registers = [capstone.x86.X86_REG_R14, capstone.x86.X86_REG_RSI, capstone.x86.X86_REG_RDI, capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9]
        )

    settings = Settings(
        opts = opts,
        rt = runtime,
        version = (7, 10, 3),
        name_to_address = {},
        address_to_name = {},
        binary = open(opts.file, "rb").read(),
        capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone_mode),
        text_offset = elffile.get_section_by_name(b'.text')['sh_offset'] - elffile.get_section_by_name(b'.text')['sh_addr'],
        data_offset = elffile.get_section_by_name(b'.data')['sh_offset'] - elffile.get_section_by_name(b'.data')['sh_addr'],
        rodata_offset = elffile.get_section_by_name(b'.rodata')['sh_offset'] - elffile.get_section_by_name(b'.rodata')['sh_addr']
    )

    symtab = elffile.get_section_by_name(b'.symtab')
    for sym in symtab.iter_symbols():
        try:
            name = str(sym.name, 'ascii')
            offset = sym['st_value']
            settings.name_to_address[name] = offset
            settings.address_to_name[offset] = name
        except:
            pass

    settings.capstone.detail = True

    parsed_version = read_version(settings)
    if parsed_version != None:
        settings = settings._replace(version = parsed_version)

    return settings
