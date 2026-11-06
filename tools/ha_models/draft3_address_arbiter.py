# SPDX-License-Identifier: EUPL-1.2
"""Model of the site-address arbiter of decision 0028 draft 3, with messages, local clocks, freezes and loss.

Two nodes A and B and a witness W. Time in seconds; every message takes DELAY seconds and is lost while its link is
down. Rules (draft 3 point 2, the counting of corosync-qdevice and the timing rule of client-go's leader election):
  - Peers heartbeat each other every HB seconds. A node that has heard its peer within PEER_DEAD sees it.
  - While the peers see each other they agree without W: the incumbent keeps the address; with no incumbent, A takes.
  - When a node cannot see its peer, the address needs W's lease: a compare-and-swap record {holder, version} at W.
    The holder renews every RETRY s; it keeps the address only while now - send_time(last successful renew) <
    RENEW_DEADLINE on its own clock, and releases it then. A challenger takes the lease only after it has observed
    the record unchanged for LEASE on its own clock (W itself keeps no clock: the record changes only by CAS).
  - A frozen node does nothing: it neither renews nor releases; its address stays configured (the kernel answers ARP)
    until it wakes, checks its deadline first, and releases if it has passed.
Faults: link AB, link AW, link BW, freeze A, freeze B, crash A, crash B (a crashed node holds nothing), each with a
start and a duration, singles and pairs.
Measured: seconds with two holders, seconds with no holder while some node could hold (it sees its peer or W).
Invariant checked: RETRY + RENEW_DEADLINE + DELAY < LEASE (the holder releases before a challenger can take).
"""
import itertools
from collections import Counter

DELAY, HB, PEER_DEAD = 1, 1, 4
RETRY, RENEW_DEADLINE, LEASE = 2, 8, 15
END = 300
STARTS = (20, 60)
DURS = (3, 10, 30, 120)
FAULTS = ("link AB", "link AW", "link BW", "freeze A", "freeze B", "crash A", "crash B")


def run(faults):
    def act(k, t):
        return any(f == k and s <= t < s + d for f, s, d in faults)
    def alive(n, t):
        return not act(f"crash {n}", t)
    def frozen(n, t):
        return act(f"freeze {n}", t)
    def link(x, y, t):
        return not act("link " + "".join(sorted(x + y)), t)
    other = {"A": "B", "B": "A"}
    holds = {"A": True, "B": False}
    heard = {"A": 0, "B": 0}
    peer_holds = {"A": False, "B": True}         # what each last heard its peer say about holding
    was_frozen = {"A": False, "B": False}                     # last time each heard its peer (local clock = global, no skew here)
    w = {"holder": "A", "version": 0}
    last_ok_send = {"A": 0, "B": None}           # send time of the last renew W accepted, per node
    observed = {"A": (0, 0), "B": (0, 0)}        # (version seen, local time first seen) per node
    inflight = []                                # (arrive_t, kind, src, dst, payload)
    two = none = 0
    frozen_two = [0]
    for t in range(END):
        # deliver messages
        keep = []
        for m in inflight:
            at, kind, src, dst, pl = m
            if at > t:
                keep.append(m)
                continue
            if kind == "hb" and alive(dst, t) and not frozen(dst, t):
                heard[dst] = t
                peer_holds[dst] = pl
            elif kind == "cas" and dst == "W":
                exp_version, sent = pl
                if w["version"] == exp_version:
                    if w["holder"] != src:
                        w["holder"] = src
                    w["version"] += 1
                    ok = True
                else:
                    ok = False
                if link(src, "W", t):
                    keep.append((t + DELAY, "cas-reply", "W", src, (ok, sent, dict(w))))
            elif kind == "read" and dst == "W" and link(src, "W", t):
                keep.append((t + DELAY, "read-reply", "W", src, dict(w)))
            elif kind in ("cas-reply", "read-reply") and alive(dst, t) and not frozen(dst, t):
                if kind == "cas-reply":
                    ok, sent, rec = pl
                    if ok and rec["holder"] == dst:
                        last_ok_send[dst] = sent
                else:
                    rec = pl
                if observed[dst][0] != rec["version"]:
                    observed[dst] = (rec["version"], t)
                observed[dst] = observed[dst] + (rec,) if len(observed[dst]) == 2 else (observed[dst][0], observed[dst][1], rec)
        inflight = keep
        for n in "AB":
            if not alive(n, t):
                holds[n] = False
                last_ok_send[n] = None
                continue
            if frozen(n, t):
                was_frozen[n] = True
                continue
            if was_frozen[n]:                           # waking: the deadline first, before anything else
                was_frozen[n] = False
                if holds[n] and (last_ok_send[n] is None or t - last_ok_send[n] >= RENEW_DEADLINE):
                    holds[n] = False
            o = other[n]
            if t % HB == 0 and link(n, o, t):
                inflight.append((t + DELAY, "hb", n, o, holds[n]))
            sees_peer = t - heard[n] <= PEER_DEAD
            if sees_peer:
                # together: the incumbent keeps; with none, A takes. W's record follows when reachable.
                rec = observed[n][2] if len(observed[n]) == 3 else None
                if holds[n] and peer_holds[n]:
                    # both hold: W's recorded holder keeps; with no record seen, A keeps
                    if (rec and rec["holder"] == o) or (not rec and n == "B"):
                        holds[n] = False
                elif holds[n]:
                    pass
                elif not holds[o] and not peer_holds[n]:
                    # nobody holds: W's recorded holder takes when it is one of the pair, else A
                    named = rec["holder"] if rec and rec["holder"] in ("A", "B") else "A"
                    if n == named:
                        holds[n] = True
                if holds[n] and t % RETRY == 0 and link(n, "W", t):
                    inflight.append((t + DELAY, "cas", n, "W", (observed[n][0], t)))
                    last_ok_send[n] = last_ok_send[n] if last_ok_send[n] is not None else t
                continue
            # alone: the address needs W's lease
            if holds[n]:
                if last_ok_send[n] is None or t - last_ok_send[n] >= RENEW_DEADLINE:
                    holds[n] = False                    # release on the deadline, own clock
                elif t % RETRY == 0 and link(n, "W", t):
                    inflight.append((t + DELAY, "cas", n, "W", (observed[n][0], t)))
            else:
                if t % RETRY == 0 and link(n, "W", t):
                    inflight.append((t + DELAY, "read", n, "W", None))
                ver, since = observed[n][0], observed[n][1]
                rec = observed[n][2] if len(observed[n]) == 3 else None
                if rec and rec["holder"] == n:
                    pass
                elif t - since >= LEASE and t % RETRY == 0 and link(n, "W", t):
                    inflight.append((t + DELAY, "cas", n, "W", (ver, t)))
                if rec and rec["holder"] == n and last_ok_send[n] is not None and t - last_ok_send[n] < RENEW_DEADLINE:
                    holds[n] = True
        hs = [n for n in "AB" if holds[n] and alive(n, t)]
        if len(hs) > 1:
            if any(frozen(n, t) for n in hs):
                frozen_two[0] += 1                      # a frozen holder: its kernel still answers for the address
            else:
                two += 1
        could = any(alive(n, t) and not frozen(n, t) and (link(n, "W", t) or link(n, other[n], t)) for n in "AB")
        if not hs and could:
            none += 1
    return two, none, frozen_two[0]


def main():
    assert RETRY + RENEW_DEADLINE + DELAY < LEASE, "the holder must release before a challenger can take"
    singles = [(f, s, d) for f in FAULTS for s in STARTS for d in DURS]
    combos = [(x,) for x in singles] + [c for c in itertools.combinations(singles, 2) if c[0][0] != c[1][0]]
    agg, worst, ex = Counter(), Counter(), {}
    kinds = Counter()
    for c in combos:
        two, none, fz = run(c)
        for k, v in (("two holders", two), ("no holder", none), ("two holders, one frozen", fz)):
            if v:
                agg[k] += 1
                if k == "two holders":
                    kinds[tuple(sorted({f for f, _, _ in c}))] += 1
                if v > worst[k]:
                    worst[k], ex[k] = v, c
    print(f"{len(combos)} scenarios; retry {RETRY}, renew deadline {RENEW_DEADLINE}, lease {LEASE}, delay {DELAY}")
    for k in ("two holders", "two holders, one frozen", "no holder"):
        print(f"  {k}: {agg[k]} scenarios, worst {worst[k]} s" + (f"  e.g. {ex[k]}" if k in ex else ""))
    for kk, cnt in kinds.most_common(6):
        print(f"    two holders with {', '.join(kk)}: {cnt}")


if __name__ == "__main__":
    main()
