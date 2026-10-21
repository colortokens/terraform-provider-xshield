#!/usr/bin/env python3
"""
Minimal stand-in for the Xshield enforcement-snapshot API, so this bundle can be
reviewed and planned without a live Xshield tenant or an AWS account.

Serves the endpoints the Terraform provider calls, from the sample snapshot in
this directory:

    GET  /api/policies/cloudsnapshots/{account}/{region}/expected
    GET  /api/policies/cloudsnapshots/{account}/{region}/versions/{n}
    GET  /api/policies/cloudsnapshots/{account}/{region}/status
    GET  /api/policies/cloudsnapshots/{account}/{region}/drift
    POST /api/policies/cloudsnapshots/{account}/{region}/receipts

Standard library only - no dependencies.

    python3 serve.py            # listens on 127.0.0.1:8087

Note: requests from the provider are RSA-PSS signed. This stand-in logs the
signature key id but does not verify it; the production API does. It also
records receipts without checking them against the snapshot, which the
production API does.
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

BASE = r"/api/policies/cloudsnapshots/(?P<account>[^/]+)/(?P<region>[^/]+)"
RE_EXPECTED = re.compile(BASE + r"/expected$")
RE_VERSION = re.compile(BASE + r"/versions/(?P<version>\d+)$")
RE_STATUS = re.compile(BASE + r"/status$")
RE_DRIFT = re.compile(BASE + r"/drift$")
RE_RECEIPTS = re.compile(BASE + r"/receipts$")

RECEIPTS = []


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})

        m = RE_EXPECTED.match(self.path)
        if m:
            print("expected  <- %s (keyId %s)" % (m.group("account"), self._key_id()), flush=True)
            return self._send(200, EXPECTED)

        m = RE_VERSION.match(self.path)
        if m:
            requested = int(m.group("version"))
            if requested != SNAPSHOT["version"]:
                return self._send(404, {
                    "status": 404,
                    "message": "this stand-in only serves version %d" % SNAPSHOT["version"],
                })
            print("snapshot  <- v%d (keyId %s)" % (requested, self._key_id()), flush=True)
            # Versioned snapshots are immutable and content-addressed.
            return self._send(200, SNAPSHOT, {
                "ETag": '"%s"' % SNAPSHOT["contentHash"],
                "Cache-Control": "public, max-age=31536000, immutable",
            })

        if RE_STATUS.match(self.path):
            applied = RECEIPTS[-1] if RECEIPTS else None
            state = "unapplied" if applied is None else (
                "converged" if applied["contentHash"] == EXPECTED["contentHash"] else "pending")
            return self._send(200, {"state": state, "expected": EXPECTED, "applied": applied})

        if RE_DRIFT.match(self.path):
            return self._send(404, {"status": 404, "message": "this stand-in has no cloud observations"})

        self._send(404, {"status": 404, "message": "not found"})

    def do_POST(self):
        if not RE_RECEIPTS.match(self.path):
            return self._send(404, {"status": 404, "message": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        receipt = json.loads(self.rfile.read(length) or b"{}")
        receipt["receiptId"] = "rcpt-" + uuid.uuid4().hex[:16]
        receipt["appliedAt"] = now()
        RECEIPTS.append(receipt)
        print("receipt   -> v%s, %d rules" % (receipt.get("version"), len(receipt.get("resources", {}).get("rules", {}))), flush=True)
        self._send(201, {"receiptId": receipt["receiptId"], "appliedAt": receipt["appliedAt"]})

    def log_message(self, *_args):
        pass  # quiet the default per-request logging; we print what matters


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8087
    print("Xshield snapshot API stand-in on http://127.0.0.1:%d" % port)
    print("  account 123456789012 / region us-east-1 / snapshot v%d"
          % SNAPSHOT["version"])
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
