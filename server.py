#!/usr/bin/env python3
"""
PassForge — Password Strength Analyzer
Run: python server.py
Open: http://localhost:7777
"""

import json, os, sys, threading, webbrowser, hashlib, urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.analyzer import analyze
from modules.generator import generate_random, generate_passphrase, generate_memorable, generate_pin, generate_batch

PORT = 7777
BASE = os.path.dirname(os.path.abspath(__file__))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, mime="text/html"):
        try:
            with open(path, "rb") as f: data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/index.html"):
            self.send_file(os.path.join(BASE, "index.html"))
        elif p == "/api/ping":
            self.send_json({"status": "online", "time": datetime.now().isoformat()})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        p = urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n)) if n else {}

        # Analyze password
        if p == "/api/analyze":
            pwd = body.get("password", "")
            result = analyze(pwd)
            self.send_json(result)

        # Generate passwords
        elif p == "/api/generate":
            style   = body.get("style", "random")
            count   = min(int(body.get("count", 5)), 20)
            length  = min(int(body.get("length", 16)), 64)
            words   = min(int(body.get("words", 4)), 8)
            sep     = body.get("separator", "-")
            upper   = body.get("upper", True)
            lower   = body.get("lower", True)
            digits  = body.get("digits", True)
            symbols = body.get("symbols", True)

            if style == "passphrase":
                results = generate_batch(count, "passphrase", words=words, separator=sep)
            elif style == "memorable":
                results = generate_batch(count, "memorable", length=length)
            elif style == "pin":
                results = generate_batch(count, "pin", length=min(length, 12))
            else:
                results = generate_batch(count, "random", length=length,
                                         upper=upper, lower=lower, digits=digits, symbols=symbols)

            analyzed = [analyze(r) for r in results]
            self.send_json({"passwords": results, "analysis": analyzed})

        # HaveIBeenPwned k-anonymity check
        elif p == "/api/breach":
            pwd = body.get("password", "")
            if not pwd:
                self.send_json({"error": "No password"}); return
            sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            try:
                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                req = urllib.request.Request(url, headers={"User-Agent": "PassForge/2.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    text = r.read().decode()
                count = 0
                for line in text.splitlines():
                    h, c = line.split(":")
                    if h == suffix:
                        count = int(c)
                        break
                self.send_json({"found": count > 0, "count": count, "sha1_prefix": prefix})
            except Exception as ex:
                self.send_json({"found": None, "error": str(ex), "sha1_prefix": prefix})

        else:
            self.send_response(404); self.end_headers()


def main():
    print(f"""
╔══════════════════════════════════════════╗
║   PASSFORGE — Password Analyzer         ║
║   http://localhost:{PORT}                  ║
║   Stop: Ctrl+C                          ║
╚══════════════════════════════════════════╝
""")
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == "__main__":
    main()
