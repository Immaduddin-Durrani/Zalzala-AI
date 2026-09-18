"""
Deterministic tools the agent can call, built per-target via
`build_tools_for_target`. Each call returns a fresh TOOLS list whose
closures are bound to that target's URL, local path, and dependency-scan
type -- so state (session cookies, exploit-db cache) never leaks between
targets. `http_request` is the one tool where the model supplies the
path/method/payload; the host is always pinned to that target's URL, and a
full URL or a different host is rejected.
"""
import csv
import io
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import requests
from langchain_core.tools import tool

NPM_CMD = shutil.which("npm") or "npm"

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

_EXPLOITDB_INDEX: dict[str, list[str]] | None = None
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


def _exploitdb_index() -> dict[str, list[str]]:
    global _EXPLOITDB_INDEX
    if _EXPLOITDB_INDEX is None:
        _EXPLOITDB_INDEX = {}
        try:
            r = requests.get(EXPLOITDB_CSV_URL, timeout=60)
            for row in csv.DictReader(io.StringIO(r.text)):
                for code in row.get("codes", "").split(";"):
                    code = code.strip()
                    if CVE_RE.match(code):
                        url = f"https://www.exploit-db.com/exploits/{row['id']}"
                        _EXPLOITDB_INDEX.setdefault(code, []).append(url)
        except requests.RequestException:
            pass
    return _EXPLOITDB_INDEX


def ensure_target_running(target_url: str) -> None:
    """Check that a target is reachable. Does not start anything -- each
    target's service must already be running (npm start for Juice Shop,
    XAMPP/Apache+MySQL for DVWA) before the agent runs against it."""
    for _ in range(15):
        try:
            if requests.get(target_url, timeout=2).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"{target_url} is not reachable. Start its service and try again.")


def build_tools_for_target(target: dict) -> list:
    """Return a fresh TOOLS list (scan_web, scan_dependencies, lookup_cve,
    http_request) bound to this one target via closure. Call once per
    target per run -- never reuse across targets, since http_session
    (cookies/auth state) and the output folder must not leak between
    targets."""
    target_url = target["url"]
    local_path = target.get("local_path")
    dependency_scan = target.get("dependency_scan", "none")

    if target_url not in CONFIG["allowed_targets"]:
        raise RuntimeError(f"Target {target_url} is not on the allowlist")

    target_output_dir = OUTPUT_DIR / target["name"]
    target_output_dir.mkdir(parents=True, exist_ok=True)

    http_session = requests.Session()
    method_re = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)$")

    @tool
    def scan_web() -> str:
        """Run a header/cookie/configuration security check against the
        approved target and return a summary of findings (missing security
        headers, insecure cookie flags, server banner disclosure, exposed
        paths). Full JSON report is written to output/<target>/web-scan-report.json.
        This is a lighter, native-Python substitute for a ZAP baseline scan --
        it covers a subset of what ZAP checks, not a full active scan."""
        report_path = target_output_dir / "web-scan-report.json"
        findings = []

        try:
            resp = http_session.get(target_url, timeout=15)
        except requests.RequestException as e:
            return f"Could not reach {target_url}: {e}"

        headers = resp.headers
        security_headers = {
            "Content-Security-Policy": "missing Content-Security-Policy header",
            "X-Frame-Options": "missing X-Frame-Options header (clickjacking risk)",
            "X-Content-Type-Options": "missing X-Content-Type-Options header",
            "Strict-Transport-Security": "missing Strict-Transport-Security header",
            "Referrer-Policy": "missing Referrer-Policy header",
        }
        for header, message in security_headers.items():
            if header not in headers:
                findings.append({"name": message, "risk": "info/low"})

        server = headers.get("Server") or headers.get("X-Powered-By")
        if server:
            findings.append({"name": f"Server banner disclosure: {server}", "risk": "low"})

        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:
                flags.append("missing Secure flag")
            rest_keys = {k.lower() for k in cookie._rest.keys()}
            if "httponly" not in rest_keys:
                flags.append("missing HttpOnly flag")
            if "samesite" not in rest_keys:
                flags.append("missing SameSite attribute")
            if flags:
                findings.append({
                    "name": f"Cookie '{cookie.name}': {', '.join(flags)}",
                    "risk": "low/medium",
                })

        for probe_path in ("/ftp/", "/.git/", "/.env", "/robots.txt"):
            try:
                r = http_session.get(target_url + probe_path, timeout=10)
                if r.status_code == 200 and probe_path != "/robots.txt":
                    findings.append({
                        "name": f"Accessible path {probe_path} returned HTTP 200 (possible exposure)",
                        "risk": "medium",
                    })
            except requests.RequestException:
                pass

        report_path.write_text(json.dumps(findings, indent=2))

        if not findings:
            return "Web scan completed: no header/cookie/exposure issues found."

        lines = [f"Web scan found {len(findings)} issue(s):"]
        for f in findings:
            lines.append(f"- {f['name']} (risk={f['risk']})")
        return "\n".join(lines)

    @tool
    def scan_dependencies() -> str:
        """Run a software-composition-analysis scan against this target's
        installed dependencies (npm audit for a Node app) and return
        vulnerable packages with CVE/GHSA identifiers and severity. Full
        JSON is written to output/<target>/npm-audit.json. Returns a plain
        'not applicable' message for targets with no supported dependency
        manifest (e.g. a PHP app like DVWA) -- that is expected, not an error."""
        if dependency_scan != "npm":
            return ("Dependency scanning is not applicable to this target "
                     "(no npm/Node manifest in scope). Skip step 2 and note "
                     "this in the final report's cve_match_note.")

        audit_path = target_output_dir / "npm-audit.json"

        if not (Path(local_path) / "package-lock.json").exists():
            return f"No package-lock.json found at {local_path} -- check this target's local_path in config.json."

        result = subprocess.run(
            [NPM_CMD, "audit", "--package-lock-only", "--json"],
            capture_output=True, text=True, timeout=60, cwd=local_path,
        )
        raw = result.stdout.strip()

        if not raw:
            return f"npm audit produced no output. stderr: {result.stderr[-2000:]}"

        audit_path.write_text(raw)
        data = json.loads(raw)

        vulns = data.get("vulnerabilities", {})
        if not vulns:
            return "npm audit found no known-vulnerable dependencies."

        ghsa_cache: dict[str, list[str]] = {}

        def ghsa_to_cves(ghsa_id: str) -> list[str]:
            if ghsa_id not in ghsa_cache:
                try:
                    r = requests.get(f"https://api.osv.dev/v1/vulns/{ghsa_id}", timeout=15)
                    aliases = r.json().get("aliases", []) if r.status_code == 200 else []
                except requests.RequestException:
                    aliases = []
                ghsa_cache[ghsa_id] = [a for a in aliases if CVE_RE.match(a)]
            return ghsa_cache[ghsa_id]

        lines = [f"npm audit found {len(vulns)} vulnerable package(s):"]
        for name, info in vulns.items():
            via = info.get("via", [])
            ghsa_ids = sorted({
                v["url"].rsplit("/", 1)[-1] for v in via
                if isinstance(v, dict) and "/advisories/GHSA-" in v.get("url", "")
            })
            cve_ids = sorted({cve for g in ghsa_ids for cve in ghsa_to_cves(g)})
            titles = [v.get("title") for v in via if isinstance(v, dict) and v.get("title")]

            id_str = ", ".join(cve_ids) if cve_ids else (", ".join(ghsa_ids) or "no advisory ID")
            lines.append(
                f"- {name} ({info.get('severity')}) [{id_str}]: "
                f"{'; '.join(titles) or 'see npm-audit.json'} [range: {info.get('range')}]"
            )

        (target_output_dir / "ghsa_cve_map.json").write_text(json.dumps(ghsa_cache, indent=2))
        return "\n".join(lines)

    @tool
    def lookup_cve(cve_id: str) -> str:
        """Look up a CVE ID in the NVD database and return its CVSS score
        and summary, plus any matching Exploit-DB entry. Pass a CVE ID like
        'CVE-2021-23337'."""
        cve_id = cve_id.strip().upper()
        if not CVE_RE.match(cve_id):
            return f"'{cve_id}' is not a valid CVE ID format (expected CVE-YYYY-NNNN)."

        time.sleep(6)
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=30,
        )
        if resp.status_code != 200:
            return f"NVD lookup for {cve_id} failed with HTTP {resp.status_code}."

        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return f"{cve_id} not found in NVD."

        cve = vulns[0]["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                score = metrics[key][0]["cvssData"]["baseScore"]
                break

        exploit_links = sorted(set(
            [r["url"] for r in cve.get("references", []) if "exploit-db.com" in r["url"]]
            + _exploitdb_index().get(cve_id, [])
        ))

        lines = [f"{cve_id}: CVSS={score}", f"Summary: {desc}"]
        lines.append(
            f"Exploit-DB reference(s): {', '.join(exploit_links)}"
            if exploit_links else "Exploit-DB reference(s): none found (checked NVD "
                                  "references and Exploit-DB's own CVE index)."
        )
        return "\n".join(lines)

    @tool
    def http_request(method: str, path: str, body: dict | None = None,
                      body_type: str = "json", auth_token: str | None = None) -> str:
        """Send a live HTTP request to this target for active testing --
        registering an account, logging in, and probing for SQL injection,
        XSS, IDOR/broken access control, etc. `path` must be a path on the
        target (e.g. '/rest/user/login' or '/login.php'), never a full URL
        or another host. `body` is a flat dict of fields to send with
        POST/PUT/PATCH. Set `body_type` to "json" for a JSON/REST API
        (Juice Shop-style) or "form" for a traditional HTML-form app
        (DVWA-style, application/x-www-form-urlencoded) -- infer which one
        this target expects from scan_web's results and from each
        response's Content-Type. `auth_token`, if you have one from a
        prior login response, is sent as an `Authorization: Bearer <token>`
        header -- for cookie-based platforms, the session cookie is
        tracked automatically between calls and you don't need to pass
        anything here. Returns the status code, content-type, and a
        truncated body preview -- only report a vulnerability as confirmed
        if this response actually demonstrates it."""
        method = method.strip().upper()
        if not method_re.match(method):
            return f"Unsupported method '{method}'. Use GET, POST, PUT, PATCH, or DELETE."
        if "://" in path or path.startswith("//"):
            return "path must be relative on this target, e.g. '/rest/user/login' -- not a full URL."
        if not path.startswith("/"):
            path = "/" + path

        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        request_kwargs = {"headers": headers, "timeout": 15}
        if body is not None:
            if body_type == "form":
                request_kwargs["data"] = body
            else:
                request_kwargs["json"] = body

        try:
            resp = http_session.request(method, target_url + path, **request_kwargs)
        except requests.RequestException as e:
            return f"Request failed: {e}"

        return (
            f"{method} {path} -> HTTP {resp.status_code}\n"
            f"Content-Type: {resp.headers.get('Content-Type')}\n"
            f"Body (truncated to 6000 chars):\n{resp.text[:6000]}"
        )

    return [scan_web, scan_dependencies, lookup_cve, http_request]