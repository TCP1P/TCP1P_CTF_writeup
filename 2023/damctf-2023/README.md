# tcl-tac-toe - web
## Description
Time to tackle tcl-tac-toe: the tricky trek towards top-tier triumph

http://tcl-tac-toe.chals.damctf.xyz/

http://161.35.58.232/

## Exploit
An attachment is provided for this challenge, which reveals the use of an uncommon programming language, namely [tcl](https://wapp.tcl-lang.org/).

![](https://i.imgur.com/scr35Wb.png)

Upon accessing the challenge's website, it becomes apparent that the site is hosting a game of tic-tac-toe, as depicted in the image below.

![](https://i.imgur.com/DCh9yyV.png)

The tic-tac-toe game happens to be impossible to solve because the bot cheats by taking two steps before it can lose.

We will use Burp Suite to intercept what happens in the background. As shown in the image below, the bot uses a type of Message Authentication Token to verify whether the input has been tampered with or not.

![](https://i.imgur.com/VE9CU7S.png)

Tampering with the request will result in a response that looks like this:

![](https://i.imgur.com/l936PJj.png)

Is it possible to bypass this and obtain the flag? It appears that we can still play the game even if we have already lost, because the function check_win in the source code does not prevent this type of undefined behavior from occurring.

```tcl 
proc check_win {board} {
    set win {{1 2 3} {4 5 6} {7 8 9} {1 4 7} {2 5 8} {3 6 9} {1 5 9} {3 5 7}}
    foreach combo $win {
        foreach player {X O} {
            set count 0
            set index [lindex combo 0]
            foreach cell $combo {
                if {[lindex $board [expr {$cell - 1}]] != $player} {
                    break
                }
                incr count
            }
            if {$count == 3} {
                return $player
            }
        }
    }
    # check if it's a tie
    if {[string first {-} $board] == -1} {
        return {tie}
    }
    return {-}
}
```

We will now open the developer console and set a breakpoint on the if statement just before `location.reload` is invoked.

![](https://i.imgur.com/AnYpY4l.png)

Keep playing the game until the alert pops up, click ok.

![](https://i.imgur.com/50g1GAz.png)

Once we hit the breakpoint, modify the value of message to a random value.

![](https://i.imgur.com/roHDtqo.png)

After making the modification, win the game.

![](https://i.imgur.com/rgVThpz.png)

After winning the game, the flag should be obtained.

![](https://i.imgur.com/0HQUkR8.png)

# Url-Stored-Notes - damctf - web
Pada challenge ini kita akan diberikan source yang bisa di cek di google drive berikut https://drive.google.com/drive/folders/18HfXS1sXOB1OB14aPjyu2flsksibD4rs .

Pada source code kita bisa menambahkan arbitary tag ke dalam html kecual `script` tag. Karna pada website tersebut menggunakan sebuah ekstensi py-script, jadi kita bisa menggunakan itu untuk mendapatkan XSS.

Pada website kita akan menemukan halaman website seperti ini untuk membuat tagnya, dan ketika kita memencet share, akan muncul link seperti gambar dibawah ini.

![](https://i.imgur.com/8SvhMqV.png)

Disini kita bisa memanipulasi url tersebut menggunakan script berikut

```python 
from base64 import b64encode
from lzma import compress, decompress
import json
from urllib.parse import quote_plus

def encodeNotes(prompt, answer, tag):
    return b64encode(compress(json.dumps([{
        "prompt": prompt,
        "answer": answer,
        "tag": tag,
    }]).encode()))

a = encodeNotes("""js.eval('alert(1)')""", "#foo&gt;", "py-script").decode()
a = "http://localhost:8080/#"+a
print(a)
```

![](https://i.imgur.com/HsiIja5.png)

# Ctf challenges git
[https://gitlab.com/osusec/damctf-2023-challenges/](https://gitlab.com/osusec/damctf-2023-challenges/ "https://gitlab.com/osusec/damctf-2023-challenges/")

# Chall Archive: 

[https://drive.google.com/drive/folders/16GdzGztpCepHJWzxZYmO4dfATQhE6ibR?usp=sharing](https://drive.google.com/drive/folders/16GdzGztpCepHJWzxZYmO4dfATQhE6ibR?usp=sharing "https://drive.google.com/drive/folders/16GdzGztpCepHJWzxZYmO4dfATQhE6ibR?usp=sharing")