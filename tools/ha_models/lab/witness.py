#!/usr/bin/env python3
"""Lab witness: one compare-and-swap record {holder, version}, no clock. POST /cas {expect, holder}: when expect equals
the version (or -1 for "my renew"), the holder is set and the version rises. GET /read."""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

rec = {"holder": "A", "version": 0}
lock = threading.Lock()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        with lock:
            self.reply({"record": dict(rec)})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with lock:
            ok = body["expect"] == rec["version"] or (body["expect"] == -1 and rec["holder"] == body["holder"])
            if ok:
                rec["holder"] = body["holder"]; rec["version"] += 1
            self.reply({"ok": ok, "record": dict(rec)})


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
