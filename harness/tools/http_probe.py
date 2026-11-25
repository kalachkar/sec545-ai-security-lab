"""Sandboxed PoC executor. The AI writes PoCs in a small JSON DSL; only this code
sends traffic, and only to the configured local app (host allowlist)."""
from __future__ import annotations

import http.client
import json
import re
import subprocess
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

VAR = re.compile(r"\{\{(\w+)\}\}")


class PocRunner:
    def __init__(self, base_url: str, login: dict, accounts: dict, container: str) -> None:
        u = urllib.parse.urlparse(base_url)
        self.host, self.port = u.hostname, u.port or 80
        if self.host not in ("localhost", "127.0.0.1"):
            raise ValueError("PoC runner only targets local apps")
        self.login_cfg, self.accounts, self.container = login, accounts, container
        self.tokens: dict[str, str] = {}

    # ---------- transport ----------
    def _send(self, method: str, path: str, headers: dict, body: bytes | None):
        if not path.startswith("/"):
            u = urllib.parse.urlparse(path)
            if u.hostname not in (self.host, None) or (u.port and u.port != self.port):
                return {"status": 0, "body": f"refused: host {u.hostname} not allowed", "refused": True}
            path = u.path + (f"?{u.query}" if u.query else "")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=20)
        try:
            conn.request(method.upper(), path, body=body, headers=headers)  # path sent as-is (no normalization)
            r = conn.getresponse()
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as exc:
            return {"status": 0, "body": f"error: {exc}"}
        finally:
            conn.close()

    def login_all(self) -> None:
        for name, acc in self.accounts.items():
            body = json.dumps({k: v.format(**acc) for k, v in self.login_cfg["body"].items()}).encode()
            r = self._send(self.login_cfg["method"], self.login_cfg["path"], {"Content-Type": "application/json"}, body)
            try:
                tok = json.loads(r["body"])[self.login_cfg["token_json_path"]]
                self.tokens[name] = tok
            except Exception:
                pass  # keep the previous token (e.g. a PoC changed this account's password)

    # ---------- DSL ----------
    @staticmethod
    def _subst(obj, env):
        if isinstance(obj, str):
            return VAR.sub(lambda m: str(env.get(m.group(1), m.group(0))), obj)
        if isinstance(obj, list):
            return [PocRunner._subst(x, env) for x in obj]
        if isinstance(obj, dict):
            return {k: PocRunner._subst(v, env) for k, v in obj.items()}
        return obj

    def _container_has(self, path: str) -> bool:
        if not re.fullmatch(r"/[\w./-]+", path or ""):
            return False
        return subprocess.run(["docker", "exec", self.container, "test", "-e", path],
                              capture_output=True).returncode == 0

    @staticmethod
    def _squash(text: str) -> str:
        """Whitespace-insensitive around JSON punctuation: '"a": 1' == '"a":1'."""
        return re.sub(r"\s*([:,{}\[\]])\s*", r"\1", text)

    @staticmethod
    def _multipart(form: dict, files: dict, boundary: str = "----sec545harness") -> bytes:
        crlf, parts = "\r\n", []
        for k, v in form.items():
            parts.append(f'--{boundary}{crlf}Content-Disposition: form-data; name="{k}"{crlf}{crlf}{v}{crlf}')
        for k, f in files.items():
            f = f if isinstance(f, dict) else {"filename": "upload.txt", "content": str(f)}
            parts.append(f'--{boundary}{crlf}Content-Disposition: form-data; name="{k}"; '
                         f'filename="{f.get("filename", "upload.txt")}"{crlf}'
                         f'Content-Type: {f.get("content_type", "application/octet-stream")}{crlf}{crlf}'
                         f'{f.get("content", "")}{crlf}')
        return ("".join(parts) + f"--{boundary}--{crlf}").encode()

    @staticmethod
    def _meets(resp: dict, expect: dict) -> bool:
        if expect.get("status") and resp["status"] not in expect["status"]:
            return False
        body = PocRunner._squash(resp["body"])
        for s in expect.get("body_contains") or []:
            if s not in resp["body"] and PocRunner._squash(str(s)) not in body:
                return False
        if expect.get("body_regex") and not re.search(expect["body_regex"], resp["body"]):
            return False
        return resp["status"] != 0

    def run(self, poc: dict) -> dict:
        env, log = {}, []
        all_ok, any_expect = True, False
        for step in (poc or {}).get("steps", [])[:12]:
            step = self._subst(step, env)
            headers = dict(step.get("headers") or {})
            if step.get("auth") and step["auth"] in self.tokens:
                headers["Authorization"] = f"Bearer {self.tokens[step['auth']]}"
            body = None
            if step.get("files"):
                body = self._multipart(step.get("form") or {}, step["files"])
                boundary = "----sec545harness"
                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            elif step.get("json") is not None:
                body = json.dumps(step["json"]).encode()
                headers.setdefault("Content-Type", "application/json")
            elif step.get("form"):
                body = urllib.parse.urlencode(step["form"]).encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif step.get("raw_body") is not None:
                body = step["raw_body"].replace("\\r\\n", "\r\n").encode()
            n = max(1, min(int(step.get("repeat") or 1), 20))
            send = lambda _: self._send(step.get("method", "GET"), step["path"], headers, body)
            if n > 1 and step.get("parallel"):
                with ThreadPoolExecutor(n) as ex:
                    resps = list(ex.map(send, range(n)))
            else:
                resps = [send(i) for i in range(n)]
            first = resps[0]
            for var, rx in (step.get("extract") or {}).items():
                m = re.search(rx, first["body"])
                if m:
                    env[var] = m.group(1) if m.groups() else m.group(0)
            expect = step.get("expect") or {}
            ok = None
            if expect:
                any_expect = True
                http_expect = {k: v for k, v in expect.items() if k != "container_file"}
                meets = [self._meets(r, http_expect) for r in resps] if http_expect else [True] * len(resps)
                ok = (sum(meets) >= 2) if n > 1 else meets[0]
                if expect.get("container_file"):
                    time.sleep(1)
                    ok = ok and self._container_has(expect["container_file"])
                all_ok = all_ok and ok
            log.append({"name": step.get("name"), "method": step.get("method"), "path": step["path"][:200],
                        "statuses": [r["status"] for r in resps], "ok": ok, "body_excerpt": first["body"][:300]})
        status = "passed" if any_expect and all_ok else ("failed" if any_expect else "no_expectation")
        return {"status": status, "steps": log}
