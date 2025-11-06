#!/usr/bin/env python3
"""
AAP 2.5 (Automation Controller API v2) client – no external deps.

Auth:
  - Preferred: Bearer token via env AAP_TOKEN
  - Fallback: Basic auth via env AAP_USER + AAP_PASS

Env:
  AAP_URL=https://ansible.ansiblelab.com
  AAP_TOKEN=6qVOc1SS42KQwT28QzsMRVz1rgvjES           # or AAP_USER / AAP_PASS
  AAP_CA_CERT=/path/ca.pem     # optional; if unset, default certs used
  AAP_VERIFY=false             # optional; set to 'false' to skip TLS verify (NOT recommended)

Usage:
  python3 aap25_cli.py --ping
  python3 aap25_cli.py --list
  python3 aap25_cli.py --launch "My Job Template" --extra-vars '{"host_limit":"web"}'
"""

import os
import ssl
import sys
import json
import time
import base64
import argparse
from urllib.request import Request, urlopen
from urllib.parse import urljoin, urlencode
from urllib.error import HTTPError, URLError

DEFAULT_TIMEOUT = 30
POLL_INTERVAL = 3

def build_ssl_ctx():
    verify_env = os.environ.get("AAP_VERIFY", "").lower()
    ca_cert = os.environ.get("AAP_CA_CERT")
    if verify_env == "false":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_cert and os.path.isfile(ca_cert):
        return ssl.create_default_context(cafile=ca_cert)
    return ssl.create_default_context()

class AAPClient:
    def __init__(self, base_url, token=None, username=None, password=None, timeout=DEFAULT_TIMEOUT, ssl_ctx=None):
        if not base_url:
            raise ValueError("AAP_URL is required")
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.ssl_ctx = ssl_ctx or build_ssl_ctx()
        self.headers = {"Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        elif username and password:
            b = f"{username}:{password}".encode("utf-8")
            self.headers["Authorization"] = "Basic " + base64.b64encode(b).decode("ascii")
        else:
            raise ValueError("Provide AAP_TOKEN or AAP_USER/AAP_PASS")

    def _url(self, path):
        if path.startswith("http"):
            return path
        path = path[1:] if path.startswith("/") else path
        return urljoin(self.base_url, path)

    def _req(self, method, path, params=None, payload=None):
        url = self._url(path)
        if params:
            # Only append if not already present
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urlencode(params)}"
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, method=method, headers=self.headers)
        try:
            with urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                content_type = resp.headers.get("Content-Type", "")
                raw = resp.read()
                if "application/json" in content_type:
                    return json.loads(raw.decode("utf-8") or "{}")
                # Some endpoints (stdout txt) return text/plain
                return raw.decode("utf-8", errors="replace")
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} {e.reason} for {url}\n{body}") from None
        except URLError as e:
            raise RuntimeError(f"Connection error for {url}: {e}") from None

    def get(self, path, params=None):
        return self._req("GET", path, params=params)

    def post(self, path, payload=None):
        return self._req("POST", path, payload=payload)

    # ---- API helpers ----
    def ping(self):
        return self.get("/api/v2/ping/")

    def paged_get(self, path, params=None):
        url = self._url(path)
        q = dict(params or {})
        while True:
            resp = self.get(url.replace(self.base_url, "/"), params=q) if url.startswith(self.base_url) else self.get(url, params=q)
            if not isinstance(resp, dict):
                break
            results = resp.get("results", [])
            for r in results:
                yield r
            next_url = resp.get("next")
            if not next_url:
                break
            url, q = next_url, None

    def list_job_templates(self, search=None):
        params = {"search": search} if search else None
        return list(self.paged_get("/api/v2/job_templates/", params=params))

    def get_job_template_by_name(self, name):
        for jt in self.paged_get("/api/v2/job_templates/", params={"name": name}):
            if jt.get("name") == name:
                return jt
        return None

    def launch_job_template(self, jt_id, *, extra_vars=None, limit=None, inventory=None, credentials=None, tags=None, skip_tags=None, verbosity=None):
        payload = {}
        if extra_vars is not None:
            if not isinstance(extra_vars, dict):
                raise ValueError("--extra-vars must be JSON object")
            payload["extra_vars"] = extra_vars
        if limit:       payload["limit"] = limit
        if inventory:   payload["inventory"] = inventory
        if credentials: payload["credentials"] = credentials
        if tags:        payload["job_tags"] = tags
        if skip_tags:   payload["skip_tags"] = skip_tags
        if verbosity is not None:
            payload["verbosity"] = verbosity
        return self.post(f"/api/v2/job_templates/{jt_id}/launch/", payload=payload)

    def get_job(self, job_id):
        return self.get(f"/api/v2/jobs/{job_id}/")

    def get_job_stdout(self, job_id, fmt="txt"):
        # fmt in {txt, html, json, ansi}
        return self.get(f"/api/v2/jobs/{job_id}/stdout/", params={"format": fmt})

def parse_args():
    p = argparse.ArgumentParser(description="AAP 2.5 API client (no external deps)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--ping", action="store_true", help="GET /api/v2/ping/")
    g.add_argument("--list", action="store_true", help="List job templates")
    g.add_argument("--launch", metavar="JOB_TEMPLATE_NAME", help="Launch a job template by name")

    p.add_argument("--search", help="Filter for --list")
    p.add_argument("--extra-vars", help="JSON string passed as extra_vars")
    p.add_argument("--limit", help="Host limit (like ansible --limit)")
    p.add_argument("--inventory", type=int, help="Inventory ID override")
    p.add_argument("--credentials", help="Comma-separated credential IDs")
    p.add_argument("--tags", help="Comma-separated job tags")
    p.add_argument("--skip-tags", help="Comma-separated skip tags")
    p.add_argument("--verbosity", type=int, choices=range(0,6), help="Verbosity 0-5")
    p.add_argument("--no-follow", action="store_true", help="Do not wait for job completion")
    return p.parse_args()

def main():
    args = parse_args()

    base_url = os.environ.get("AAP_URL")
    token = os.environ.get("AAP_TOKEN")
    user  = os.environ.get("AAP_USER")
    pwd   = os.environ.get("AAP_PASS")
    if not base_url:
        sys.exit("Set AAP_URL (e.g., https://controller.example.com)")

    client = AAPClient(base_url, token=token, username=user, password=pwd)

    if args.ping:
        print(json.dumps(client.ping(), indent=2))
        return

    if args.list:
        jts = client.list_job_templates(search=args.search)
        if not jts:
            print("No job templates found.")
            return
        for jt in jts:
            proj = jt.get("project")
            inv  = jt.get("inventory")
            print(f"- [{jt['id']}] {jt['name']}  (project={proj}, inventory={inv})")
        return

    if args.launch:
        jt = client.get_job_template_by_name(args.launch)
        if not jt:
            sys.exit(f"Job Template not found: {args.launch}")

        extra_vars = None
        if args.extra_vars:
            try:
                extra_vars = json.loads(args.extra_vars)
            except json.JSONDecodeError as e:
                sys.exit(f"--extra-vars must be valid JSON: {e}")

        creds = None
        if args.credentials:
            try:
                creds = [int(x.strip()) for x in args.credentials.split(",") if x.strip()]
            except ValueError:
                sys.exit("--credentials must be comma-separated integers")

        launch = client.launch_job_template(
            jt_id=jt["id"],
            extra_vars=extra_vars,
            limit=args.limit,
            inventory=args.inventory,
            credentials=creds,
            tags=args.tags,
            skip_tags=args.skip_tags,
            verbosity=args.verbosity
        )

        # Job or workflow job id
        job_id = launch.get("job") or launch.get("id")
        if not job_id:
            print(json.dumps(launch, indent=2))
            sys.exit("Launch returned no job id (is this a workflow?)")

        print(f"Launched job_id={job_id}")

        if args.no_follow:
            return

        # Poll
        while True:
            job = client.get_job(job_id)
            status = job.get("status")
            print(f"Status: {status}", flush=True)
            if status in {"successful", "failed", "error", "canceled"}:
                break
            time.sleep(POLL_INTERVAL)

        print("\n=== Job stdout ===")
        try:
            out = client.get_job_stdout(job_id, fmt="txt")
            sys.stdout.write(out if isinstance(out, str) else json.dumps(out, indent=2))
            sys.stdout.write("\n")
        except Exception as e:
            print(f"(could not fetch stdout: {e})")

        if status != "successful":
            sys.exit(f"Job completed with status: {status}")

if __name__ == "__main__":
    main()
