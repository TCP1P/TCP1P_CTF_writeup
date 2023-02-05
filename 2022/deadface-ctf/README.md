# OSINT
## Under Public Scrutiny
Cukup dari keyword github di https://ghosttown.deadface.io/ 
![](Pasted%20image%2020221016084928.png)

ketemu thread ini: [https://ghosttown.deadface.io/t/made-a-github-link-for-projects/66](https://ghosttown.deadface.io/t/made-a-github-link-for-projects/66 "https://ghosttown.deadface.io/t/made-a-github-link-for-projects/66") (edited)

katanya akun githubnya deadf4c3 
ada 1 repo sus, got flag https://github.com/deadf4c3/tarrasque

## Grave Digger 1

Untuk challenge ini kita perlu ssh ke user crypto\_vamp lalu ketik env

```
crypto_vamp@1d2d67359e3a:/proc$ env
GRAVEDIGGER1=flag{d34dF4C3_en1roN_v4r}
HOSTNAME=1d2d67359e3a
PWD=/proc
HOME=/home/crypto_vamp
TERM=xterm
TMOUT=1600
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
OLDPWD=/
```

# REV
## Monstrosity
Diberikan file binary, disini yang unik adalah program tersebut sectionnya di encrypt dan akan didecrypt runtime. Cukup dump menggunakan gdb dan dapet binary yg bisa dianalisis 

![](Pasted%20image%2020221016085136.png)

program akan meminta input dan melakukan cek dengan input tersebut:

![](Pasted%20image%2020221016085148.png)

bisa dilihat, input user akan dicompare dengan var v13
dimana disini var v13 diencrypt dengan xor 0x1e:

![](Pasted%20image%2020221016085202.png)

setelah decrypt dengan saibersep, dapet jawabannya and got flag

![](Pasted%20image%2020221016085210.png)

## Cereal Killer 02 (REV)
Diberi program .NET yang dimana disini flag diencrypt dengan aes menggunakan jawaban. validasi jawab disini menggunakan md5, dimana md5nya adalah aee1ee5262757cf67b619ff63e9672b6, setelah menggunakan crackstation untuk mencari jawabannya, dapet hasil peanutbuttercrunch. Enter the flag and boom got flag
![](Pasted%20image%2020221016084856.png)

![](Pasted%20image%2020221016084906.png)


# PWN
## Easy Creds
untuk soal ini kita hanya perlu menggunakan john

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt
```

untuk identifiernya saya menggunakan https://hashes.com/en/tools/hash_identifier

## Crack Database
diberikan sebuah file keepas, kita akan crack dengan john, masalahnya wordlist yg dipake gatawu,

kita coba cari di ghostown https://ghosttown.deadface.io
ternyata pada post More Bitcoin`$$$$$` user bernama mirveal memberikan wordlists, kita coba gunakan itu untuk membuka crack passwordnya..
didapatlah passwordnya complexpassword

buka di keepass copy password pada title PWN07-....
flag{breaking_the_law}

![](Pasted%20image%2020221016090134.png)

![](Pasted%20image%2020221016090147.png)

![](Pasted%20image%2020221016090154.png)

## Grave Digger 2

kita perlu masuk menggunakan ssh dari grave digger 1

```
ssh crypto_vamp@env.deadface.io
# password: 123456789q
```

read file gravedigger2 menggunakan

```
/opt/reader -f gravedigger2
```

maka nanti akan muncul qr code, setelah itu kita scan qrcodenya dan nanti akan mendapatkan flagnya.

# crypto
## Two Dead Boys

diberikan string yang di encrypt vigenere

"qlsn{Pvelnnad Aumjcnyg: Ibrwpaty ENLECPZNYG!}"

karena kita sudah tahu 4 huruf pertama maka kita dapat memanfaatkan fitur known plaintext di dcode.fr tinggal pake mode bruteforce saja maka flag muncul

flag{Critical Thinking: Question EVERYTHING!}

## "D" is for Dumb Mistakes

p = 1049
q = 2063
e = 777887

untuk dapat d atau privatekey kita bisa menggunakan fungsi inversemod pada gympy2 atau make dcode.fr

N = (p-1)*(q-1)
d = (e,N)
d = 1457215

flag{d=1457215}

## "D" if for Decryption

masih berhubungan dengan soal pertaam tapi kali ini kita diberikan cipher text untuk di decrypt yang mana hasilnya anggka yang direpresentasikan urutan alphabet

untuk scriptnya 
```python
from Crypto.Util.number import inverse, long_to_bytes

p = 1049
q = 2063
e = 777887
d = 1457215
n = p*q

data = [992478,1726930,1622358,1635603,1385290]

flag = []
for i in data:
    flag +=long_to_bytes(pow(i,d,n))

print('flag{',end="")
for i in flag: print(chr(64+i).lower(),end="")
print('}')
```


# stegano
## The Goodest Boy
diberikan gambar ANJING! wkwkw dalam jika dilihat string ada ascci bertuliskan password:borkbork

coba extract pake tool steghide ternyta ada pdf yang berisi flag
flag{whos_A_g00d_boi_bork_bork}

# SQL
## Counting heads
diberikan file .sql, import sqlnya, terus masuk ke database nya, masukin query flag{2400}

![](Pasted%20image%2020221016085502.png)

## The Faculty
lanjutan sql sebelumnya, masukin query

select count(r.user_id) from roles_assigned r join users u on r.user_id=u.user_id where not role_id=1;

flag{627}

![](Pasted%20image%2020221016085646.png)

## Let's Hash It Out
diberi clue DEADFACE menargetkan sebuah user, lihat password user tersebut.

langsung cari di https://ghosttown.deadface.io/ ketemu post Database Question  lanjut cari siapa user yang dimaksud, ternyata role Administration, selanjutnya kita query role Administration pada bagian passwordnya

flag{b487af41779cffb9572b982e1a0bf83f0eafbe05}

![](Pasted%20image%2020221016090238.png)

![](Pasted%20image%2020221016090243.png)

## Fall Classes
diberikan pertanyaan berapa banyak kelas musim semi yang unik.
langsung bikin query select count(distinct tc.course_id) from terms t join term_courses tc on t.term_id=tc.term_id where t.term_id=2;
flag{405}

![](Pasted%20image%2020221016090323.png)

# Bonus

## Contact

Dalam ssh di user crypto\_vamp kita inputkan man reader untuk melihat manual dari program yang dibuat lilith

```
crypto_vamp@3e71a870077f:/home/spookyboi$ man reader
man(8)                                                                    reader man page                                                                   man(8)

NAME
       reader - read files as lilith

SYNOPSIS
       reader [OPTIONS] [FILENAME]

DESCRIPTION
       reader is developed to help crypto_vamp and other new recruits read privileged files until their vetting process is complete.

OPTIONS
       -f, --file FILENAME
              Read the contents of FILENAME.

       -c, --command COMMAND
              Execute a command (for troubleshooting purposes ONLY).

       -h, --help
              View the help information.

       -v, --version
              View the version information.

       BUGS   No known bugs.

AUTHOR
       Lilith (bl0ody_mary@deadface.io)

1.3.1
```

maka disitu akan ada emailnya si lilith