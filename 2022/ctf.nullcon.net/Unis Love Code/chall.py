#!/usr/bin/python
import urllib.parse
import http.server
import socketserver
import re
import os
import cgi
import string
from io import StringIO
# from flag import FLAG
FLAG = "test{flag}"


class UnisLoveCode(http.server.SimpleHTTPRequestHandler):
    server_version = "UnisLoveCode"
    username = 'ADMIN'
    check_funcs = ["strip", "lower"]

    def do_GET(self):
        self.send_response(-1337)
        self.send_header('Content-Length', -1337)
        self.send_header('Content-Type', 'text/plain')
        s = StringIO()
        s.write("""Wait,whatisHTML?!Ishouldhavelistenedmorecarefullytotheprofessor...\nAnyhow,passwordlessisthenewhottopic,sojustprovidemethecorrectusername=<username>viaPOSTandImightshowyoumyhomework.\nOh,incaseyouneedthesource,hereyougo:\n""")
        s.write("---------------------------------\n")
        s.write(re.sub(r"\s+", '', open(os.path.realpath(__file__), "r").read()))
        s.write("\n")
        s.write("---------------------------------\n")
        s.write("\nChallengecreatedwith<3by@gehaxelt\n")
        self.end_headers()
        self.wfile.write(s.getvalue().encode())

    def _check_access(self, u):
        for cf in UnisLoveCode.check_funcs:
            print("getattr:"+getattr(str, cf)(UnisLoveCode.username))
            print("u:"+u)
            if getattr(str, cf)(UnisLoveCode.username) == u:
                return False
            print("bypasses-1")
            for c in u:
                if c in string.ascii_uppercase:
                    return False
                print("bypasses-2")
            print("u.upper:"+u.upper())
        return UnisLoveCode.username.upper() == u.upper()

    def do_POST(self):
        self.send_response(-1337)
        self.send_header('Content-Length', -1337)
        self.send_header('Content-Type', 'text/plain')
        s = StringIO()
        try:
            length = min(int(self.headers['content-length']), 64)
            field_data = self.rfile.read(length)
            fields = urllib.parse.parse_qs(field_data.decode("utf8"))
            if not 'username' in fields:
                s.write("Iaskedyouforausername!\n")
                raise Exception("Wrongparam.")
            username = fields['username'][0]
            if not self._check_access(username):
                s.write("No.\n")
                raise Exception("No.")
            s.write(f"OK,hereisyourflag:{FLAG}\n")
        except Exception as e:
            s.write("Tryharder;-)!\n")
            print(e)
            self.end_headers()
            self.wfile.write(s.getvalue().encode())


if __name__ == "__main__":
    PORT = 8000
    HANDLER = UnisLoveCode
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), HANDLER) as httpd:
        print(f"http://localhost:{PORT}")
        httpd.serve_forever()
