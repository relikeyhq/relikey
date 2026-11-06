#!/usr/bin/env python3
"""Prototype of the 0028 draft 3 address arbiter (lab only). One process per node.

Peers heartbeat over UDP every HB s; the witness is an HTTP compare-and-swap record. Rules as in the decision:
together, the holder keeps (both: the witness's recorded holder keeps, else A); none: the recorded holder takes,
else A. Apart: hold only with the witness's lease, released at RENEW_DEADLINE after the send time of the last
accepted renew (monotonic clock); a challenger takes only after seeing the record unchanged for LEASE.
Holding = the site address on this node (ip addr add) plus gratuitous ARP; with VMAC=1 the address lives on a
macvlan with a fixed MAC, so the same MAC moves. A file /tmp/cut-peer drops peer heartbeats (a cut between nodes).
"""
import json, os, socket, subprocess, sys, time, urllib.request

ME, PEER, PEER_IP, WIT = os.environ["ME"], os.environ["PEER"], os.environ["PEER_IP"], os.environ["WITNESS"]
VIP, DEV, VMAC = os.environ["VIP"], os.environ.get("DEV", "eth0"), os.environ.get("VMAC") == "1"
HB, PEER_DEAD, RETRY, RENEW_DEADLINE, LEASE = 1.0, 4.0, 2.0, 8.0, 15.0
mono = time.monotonic


def log(*a):
    print(f"{time.time():.3f} {ME}", *a, flush=True)


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def take():
    if VMAC:
        sh(f"ip link add vip0 link {DEV} address 02:00:5e:00:01:64 type macvlan mode bridge 2>/dev/null; ip link set vip0 up")
        sh(f"ip addr add {VIP}/24 dev vip0")
        sh(f"arping -U -c 3 -I vip0 {VIP} >/dev/null 2>&1 &")
    else:
        sh(f"ip addr add {VIP}/24 dev {DEV}")
        sh(f"arping -U -c 3 -I {DEV} {VIP} >/dev/null 2>&1 &")
    log("TAKE")


def release():
    if VMAC:
        sh("ip link del vip0")
    else:
        sh(f"ip addr del {VIP}/24 dev {DEV}")
    log("RELEASE")


def witness(path, body=None):
    try:
        req = urllib.request.Request(f"http://{WIT}:8080/{path}", data=json.dumps(body).encode() if body else None,
                                     method="POST" if body else "GET")
        with urllib.request.urlopen(req, timeout=1.5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 7700))
    s.setblocking(False)
    holds = os.environ.get("START_HOLD") == "1"
    if holds:
        take()
    heard, peer_holds = mono(), not holds
    rec, seen_ver, seen_at, last_ok_send = None, None, mono(), mono() if holds else None
    next_hb = next_w = 0.0
    while True:
        now = mono()
        try:
            while True:
                data, _ = s.recvfrom(64)
                if not os.path.exists("/tmp/cut-peer"):
                    heard, peer_holds = mono(), data == b"1"
        except BlockingIOError:
            pass
        if now >= next_hb:
            next_hb = now + HB
            if not os.path.exists("/tmp/cut-peer"):
                try:
                    s.sendto(b"1" if holds else b"0", (PEER_IP, 7700))
                except OSError:
                    pass
        if now >= next_w:                      # read or renew the witness every RETRY
            next_w = now + RETRY
            sent = mono()
            if holds:
                r = witness("cas", {"expect": rec["version"] if rec else -1, "holder": ME})
                if r and r.get("ok"):
                    last_ok_send = sent
            else:
                r = witness("read")
            if r:
                rec = r["record"]
                if rec["version"] != seen_ver:
                    seen_ver, seen_at = rec["version"], mono()
        together = now - heard <= PEER_DEAD
        named = rec["holder"] if rec and rec["holder"] in (ME, PEER) else "A"
        if together:
            if holds and peer_holds and named != ME:
                holds = False; release()
            elif not holds and not peer_holds and named == ME:
                holds, last_ok_send = True, mono(); take()
        else:
            if holds and (last_ok_send is None or now - last_ok_send >= RENEW_DEADLINE):
                holds = False; release()
            elif not holds and rec and now - seen_at >= LEASE:
                r = witness("cas", {"expect": rec["version"], "holder": ME})
                if r and r.get("ok"):
                    rec, seen_ver, seen_at, last_ok_send = r["record"], r["record"]["version"], mono(), mono()
                    holds = True; take()
        time.sleep(0.1)


if __name__ == "__main__":
    main()
