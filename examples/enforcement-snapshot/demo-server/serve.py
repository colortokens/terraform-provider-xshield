#!/usr/bin/env python3
"""
Minimal stand-in for the Xshield enforcement-snapshot API, so this bundle can be
reviewed and planned without a live Xshield tenant or an AWS account.

Serves the endpoints the Terraform provider calls, from the sample snapshot in
this directory, for its account and region. Any other account or region gets
Xshield's answer for one with nothing published, so a workspace pointed at it
plans no change:

    GET  /api/policies/cloudsnapshots/aws/{account}/{region}/expected
    GET  /api/policies/cloudsnapshots/aws/{account}/{region}/versions/{version}
    GET  /api/policies/cloudsnapshots/aws/{account}/{region}/status
    POST /api/policies/cloudsnapshots/aws/{account}/{region}/receipts

A version is the snapshot's content hash, as Xshield names it. The status has no
drift: this stand-in receives no cloud observations.

Standard library only - no dependencies.

    python3 serve.py            # listens on 127.0.0.1:8087

Requests from the provider are RSA-PSS signed. This stand-in logs the
signature key id but does not verify it; the production API does. It checks a
receipt against the snapshot the way the production API does, so a module that
leaves a resource out fails here first.
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = json.load(open(os.path.join(HERE, "sample-snapshot.json")))
EXPECTED = json.load(open(os.path.join(HERE, "sample-expected.json")))

BASE = r"/api/policies/cloudsnapshots/(?P<cloud>[^/]+)/(?P<account>[^/]+)/(?P<region>[^/]+)"
RE_EXPECTED = re.compile(BASE + r"/expected$")
RE_VERSION = re.compile(BASE + r"/versions/(?P<version>[0-9a-f]+)$")
RE_STATUS = re.compile(BASE + r"/status$")
RE_RECEIPTS = re.compile(BASE + r"/receipts$")

RECEIPTS = []

NOT_PUBLISHED = {"status": 404, "code": "notPublished", "message": "no snapshot published for this account and region"}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def receipt_gaps(resources):
    """The keys a receipt leaves out or invents, as the production API names them."""
    plan = SNAPSHOT["aws"]
    want = {
        "securityGroups": set(plan["securityGroups"]),
        "rules": set(plan["ingressRules"]) | set(plan["egressRules"]),
        "attachments": set(plan["interfaceAttachments"]),
    }
    gaps = {}
    for name, keys in want.items():
        got = set((resources.get(name) or {}).keys())
        if keys - got:
            gaps[name + "Missing"] = sorted(keys - got)
        if got - keys:
            gaps[name + "Unknown"] = sorted(got - keys)
    return gaps


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, extra_headers=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _key_id(self):
        auth = self.headers.get("Authorization", "")
        return auth.split('keyId="')[1].split('"')[0] if 'keyId="' in auth else "-"

    def _published(self, m):
        return (m.group("cloud") == SNAPSHOT["cloudProvider"] and m.group("account") == SNAPSHOT["cloudAccountId"]
                and m.group("region") == SNAPSHOT["region"])

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})

        m = re.match(BASE + r"/", self.path)
        if m and not self._published(m):
            print("unpublished <- %s/%s" % (m.group("account"), m.group("region")), flush=True)
            if RE_VERSION.match(self.path):
                return self._send(404, {"status": 404, "message": "unknown snapshot version"})
            return self._send(404, NOT_PUBLISHED)

        m = RE_EXPECTED.match(self.path)
        if m:
            print("expected  <- %s (keyId %s)" % (m.group("account"), self._key_id()), flush=True)
            return self._send(200, EXPECTED)

        m = RE_VERSION.match(self.path)
        if m:
            requested = m.group("version")
            if requested != SNAPSHOT["version"]:
                return self._send(404, {"status": 404, "message": "unknown snapshot version"})
            print("snapshot  <- %s (keyId %s)" % (requested[:12], self._key_id()), flush=True)
            # Versioned snapshots are immutable and content-addressed.
            return self._send(200, SNAPSHOT, {
                "ETag": '"%s"' % SNAPSHOT["version"],
                "Cache-Control": "public, max-age=31536000, immutable",
            })

        if RE_STATUS.match(self.path):
            applied = RECEIPTS[-1] if RECEIPTS else None
            state = "unapplied" if applied is None else (
                "converged" if applied["version"] == EXPECTED["version"] else "pending")
            return self._send(200, {"state": state, "expected": EXPECTED, "applied": applied, "notices": []})

        self._send(404, {"status": 404, "message": "not found"})

    def do_POST(self):
        m = RE_RECEIPTS.match(self.path)
        if not m:
            return self._send(404, {"status": 404, "message": "not found"})
        if not self._published(m):
            return self._send(404, NOT_PUBLISHED)
        length = int(self.headers.get("Content-Length", 0))
        receipt = json.loads(self.rfile.read(length) or b"{}")
        if receipt.get("version") != SNAPSHOT["version"]:
            return self._send(404, {"status": 404, "message": "receipt references an unknown snapshot version"})
        gaps = receipt_gaps(receipt.get("resources") or {})
        if gaps:
            print("receipt   x %s" % json.dumps(gaps), flush=True)
            return self._send(422, {"status": 422, "message": "receipt does not account for exactly the snapshot's resources", "details": gaps})
        receipt["receiptId"] = "rcpt-" + uuid.uuid4().hex[:16]
        receipt["appliedAt"] = now()
        RECEIPTS.append(receipt)
        res = receipt.get("resources", {})
        print("receipt   -> %s: %d groups, %d rules, %d attachments" % (receipt.get("version")[:12], len(res.get("securityGroups", {})),
              len(res.get("rules", {})), len(res.get("attachments") or {})), flush=True)
        self._send(201, {"receiptId": receipt["receiptId"], "appliedAt": receipt["appliedAt"]})

    def log_message(self, *_args):
        pass  # quiet the default per-request logging; we print what matters


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8087
    print("Xshield snapshot API stand-in on http://127.0.0.1:%d" % port)
    print("  %s account %s / region %s / snapshot %s; any other account or region has nothing published"
          % (SNAPSHOT["cloudProvider"], SNAPSHOT["cloudAccountId"], SNAPSHOT["region"], SNAPSHOT["version"][:12]))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
