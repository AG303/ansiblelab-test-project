#!/usr/bin/env python3
"""
AAP 2.5 (Automation Controller) API example:
- Auth via Bearer token (preferred) or username/password
- GET /api/v2/ endpoints with pagination
- List Job Templates
- Launch a Job Template by name
- Poll job status and fetch stdout

Env vars:
  AAP_URL=https://ansible.ansiblelab.com
  AAP_TOKEN=<6qVOc1SS42KQwT28QzsMRVz1rgvjES>   # preferred
  AAP_USER=<username>                                  # fallback
  AAP_PASS=<password>                                  # fallback
  REQUESTS_CA_BUNDLE=/path/to/ca.pem                   # optional (or set verify=False below)

Usage:
  python aap_example.py --list
  python aap_example.py --launch "My Job Template" --extra-vars '{"target":"web"}'
"""

import os
import sys
import time
import json
import argparse
import requests
from urllib.parse import urljoin

DEFAULT_TIMEOUT = 30
POLL_INTERVAL = 3

class AAPClient:
    def __init__(self, base_url, token=None, username=None, password=None, verify=False, timeout=DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.verify = verify
        self.s = requests.Session()
        self.s.headers.update({"Content-Type": "application/json"})
        if token:
            self.s.headers.update({"Authorization": f"Bearer {token}"})
        elif username and password:
            self.s.auth = (username, password)
        else:
            raise ValueError("Provide AAP_TOKEN or AAP_USER/AAP_PASS")

    def _url(self, path):
        if path.startswith("http"):
            return path
        if path.startswith("/"):
            path = path[1:]
        return urljoin(self.base_url, path)

    def get(self, path, params=None):
        r = self.s.get(self._url(path), params=params, timeout=self.timeout, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def post(self, path, payload=None):
        r = self.s.post(self._url(path), data=json.dumps(payload or {}), timeout=self.timeout, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def paged_get(self, path, params=None):
        """Iterate through paginated results under /api/v2/ (next links)."""
        params = params or {}
        url = self._url(path)
        while url:
            r = self.s.get(url, params=params, timeout=self.timeout, verify=self.verify)
            r.raise_for_status()
            data = r.json()
            for res in data.get("results", []):
                yield res
            url = data.get("next")
            params = None  # only pass params on first call

    # Convenience helpers
    def ping(self):
        return self.get("/api/v2/ping/")

    def list_job_templates(self, search=None):
        params = {"search": search} if search else None
        return list(self.paged_get("/api/v2/job_templates/", params=params))

    def get_job_template_by_name(self, name):
        for jt in self.paged_get("/api/v2/job_templates/", params={"name": name}):
            if jt.get("name") == name:
                return jt
        return None

    def launch_job_template(self, jt_id, extra_vars=None, limit=None, inventory=None, credentials=None, tags=None, skip_tags=None, verbosity=None):
        payload = {}
        if extra_vars:
            # extra_vars must be a dict; the API will JSON-encode it.
            payload["extra_vars"] = extra_vars
        if limit:
            payload["limit"] = limit
        if inventory:
            payload["inventory"] = inventory
        if credentials:
            payload["credentials"] = credentials  # list of credential IDs
        if tags:
            payload["job_tags"] = tags
        if skip_tags:
            payload["skip_tags"] = skip_tags
        if verbosity is not None:
            payload["verbosity"] = verbosity

        launch_url = f"/api/v2/job_templates/{jt_id}/launch/"
        return self.post(launch_url, payload)

    def get_job(self, job_id):
        return self.get(f"/api/v2/jobs/{job_id}/")

    def get_job_stdout(self, job_id, fmt="txt"):
        # txt, html, json, ansi
        r = self.s.get(self._url(f"/api/v2/jobs/{job_id}/stdout/"), params={"format": fmt}, timeout=self.timeout, verify=self.verify)
        r.raise_for_status()
        return r.text

def parse_args():
    p = argparse.ArgumentParser(description="Query AAP 2.5 (Automation Controller API v2)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--ping", action="store_true", help="Call /api/v2/ping/")
    g.add_argument("--list", action="store_true", help="List job templates")
    g.add_argument("--launch", metavar="JOB_TEMPLATE_NAME", help="Launch a job template by name")

    p.add_argument("--search", help="Search filter for --list")
    p.add_argument("--extra-vars", help="JSON string for extra_vars when launching")
    p.add_argument("--limit", help="Host limit for a run (like CLI --limit)")
    p.add_argument("--inventory", type=int, help="Inventory ID override")
    p.add_argument("--credentials", help="Comma-separated credential IDs")
    p.add_argument("--tags", help="Comma-separated job tags")
    p.add_argument("--skip-tags", help="Comma-separated job skip tags")
    p.add_argument("--verbosity", type=int, choices=range(0,6), help="Verbosity 0-5")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS verification (not recommended)")
    p.add_argument("--no-follow", action="store_true", help="Do not follow job to completion")
    return p.parse_args()

def main():
    args = parse_args()

    base_url = os.environ.get("AAP_URL")
    token = os.environ.get("AAP_TOKEN")
    user = os.environ.get("AAP_USER")
    pwd = os.environ.get("AAP_PASS")
    if not base_url:
        sys.exit("Set AAP_URL (e.g., https://aap.example.com)")

    verify = not args.no_verify
    client = AAPClient(base_url=base_url, token=token, username=user, password=pwd, verify=verify)

    if args.ping:
        print(json.dumps(client.ping(), indent=2))
        return

    if args.list:
        jts = client.list_job_templates(search=args.search)
        if not jts:
            print("No job templates found.")
            return
        for jt in jts:
            print(f"- [{jt['id']}] {jt['name']}  (project={jt.get('project', None)}, inventory={jt.get('inventory', None)})")
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
                creds = [int(c.strip()) for c in args.credentials.split(",") if c.strip()]
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

        job_id = launch.get("job")
        if not job_id:
            # Could be a workflow job; handle generically
            job_id = launch.get("id")
        print(f"Launched: job_id={job_id}")

        if args.no_follow or not job_id:
            return

        # Poll to completion
        while True:
            job = client.get_job(job_id)
            status = job.get("status")
            finished = job.get("finished")
            print(f"Status: {status}", flush=True)
            if status in {"successful", "failed", "error", "canceled"}:
                break
            time.sleep(POLL_INTERVAL)

        print("\n=== Job stdout ===")
        try:
            print(client.get_job_stdout(job_id, fmt="txt"))
        except Exception as e:
            print(f"(could not fetch stdout: {e})")

        if status != "successful":
            sys.exit(f"Job completed with status: {status}")

if __name__ == "__main__":
    main()
