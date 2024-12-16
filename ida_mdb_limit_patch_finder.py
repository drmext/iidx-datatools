import idaapi
import idc
import idautils

OUTPUT = []
DEBUG = False


def debug_log(s):
    if DEBUG:
        print(s)


def dump_hex(ea, num_bytes):
    hex_bytes = idaapi.get_bytes(ea, num_bytes)
    hex_str = " ".join([f"{byte:02X}" for byte in hex_bytes])
    return hex_str


for find_mdb in idautils.Strings():
    if str(find_mdb)[-14:] == "music_data.bin":
        debug_log(f"Found /data/info/?/music_data.bin at 0x{find_mdb.ea:X}")
        for xref in idautils.XrefsTo(find_mdb.ea):
            debug_log(f"Xref to 0x{xref.to:X} found at 0x{xref.frm:X}")
            mdb_path = xref
            idc.jumpto(xref.frm)

for ea in idautils.Heads(mdb_path.frm + 10, mdb_path.frm + 70):
    insn = idaapi.insn_t()
    if (
        idaapi.decode_insn(insn, ea)
        and insn.get_canon_mnem() == "lea"
        and insn.ops[0].type == idaapi.o_reg
        and insn.ops[0].reg == 2 # rdx
        and insn.ops[1].type == idaapi.o_mem
    ):
        mem_address = insn.ops[1].addr
        mem_label = idc.get_name(mem_address)
        if mem_label.startswith("unk_"):
            debug_log(f"Found 'lea rdx' at 0x{ea:X} with 0x{mem_address:X} ({mem_label})")
            dont_patch = ea


def lea_to_mov(addr):
    for xref in idautils.XrefsTo(addr, idaapi.XREF_ALL):
        xref_address = xref.frm
        if xref_address != dont_patch and dump_hex(xref_address, 2)[-2:] == "8D":
            debug_log(f"Xref to 0x{addr:X} found at 0x{xref_address:X}")
            OUTPUT.append(f"0x{idaapi.get_fileregion_offset(xref_address+1):X}: 8D -> 8B")


lea_to_mov(mem_address)
lea_to_mov(mem_address + 0x10)


for ea in idautils.Heads(mdb_path.frm, mdb_path.frm + 20):
    insn = idaapi.insn_t()
    if (
        idaapi.decode_insn(insn, ea)
        and insn.get_canon_mnem() == "test"
        and insn.ops[0].type == idaapi.o_reg
        and insn.ops[0].reg == 0 # eax
        and insn.ops[1].reg == 0 # eax
    ):
        debug_log(f"Found 'test eax, eax' at 0x{ea:X}")
        big_patch_start = ea

big_patch_off = dump_hex(ea, 59)

big_patch_on = "B9 00 00 60 00 BA 01 00 00 00 E8 "
jcalloc_base_addr = idc.get_name_ea_simple("j__calloc_base")
if jcalloc_base_addr == idc.BADADDR:
    raise SystemExit("couldn't find address for j__calloc_base yet. rerun the script after IDA is finished loading.")
relative_address = jcalloc_base_addr - (big_patch_start + 10 + 5)
big_patch_on += " ".join([hex(relative_address)[2:][i : i + 2] for i in range(0, 5, 2)][::-1]).upper()
big_patch_on += f" 00 EB 20 48 89 02 48 83 C0 10 48 89 42 10 48 83 E8 10 48 89 C2 89 D9 41 B8 00 00 60 00 EB 0D 90 90 90 90 {big_patch_off[147:167]} EB D7 FF"

OUTPUT.append(f"0x{idaapi.get_fileregion_offset(big_patch_start):X}: {big_patch_off} -> {big_patch_on}")

print()
print("\n".join(OUTPUT))
