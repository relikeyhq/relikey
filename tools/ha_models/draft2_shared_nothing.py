# SPDX-License-Identifier: EUPL-1.2
"""Model of decision 0028 draft 2: two whole edges sharing nothing, a third vote only for the site's address.

Nodes A and B (each a single-node edge: own agent, own Warpgate), witness W, the core (desk). A lease L for person P is
live from t=0; the desk revokes it at t=REVOKE. Each node pulls every PULL seconds when it reaches the core; a node
that cannot reach the core keeps its last verified bundle until the lease's horizon (HORIZON). A node that applies a
bundle without L removes P's role at that tick and reports the removal at its next report (same moment as the pull).
Faults: crash of a node (it returns with its state: the agent's floors survive, decision 0011), the A-core, B-core,
A-B, A-W, B-W links, for a start and a duration.

Address arbiter: a node holds the address only while it holds a majority of {self, peer, W}; W gives its vote to the
holder it last voted for while that one still reaches it (a lease at W renewed every RENEW s, expiring after WTTL s),
the peer votes for a node it reaches when the peer itself does not hold the address. A node notices a lost majority
at its next RENEW.

Properties:
  P1 no node holds L's role after max(its first successful pull after REVOKE, ...) : role held at t only if the node
     has not pulled successfully since REVOKE and t < HORIZON.
  P2 leaver proof: the desk says "removed" only when no node holds the role. Checked for the rule in KeyClerk today
     (first confirmation per edge) and the proposed rule (every node of the edge confirmed).
  P3 address: seconds with two holders (reconnects, no safety cost) and seconds with no holder while some node reaches
     a majority (an outage the arbiter caused).
"""
import itertools
from collections import Counter

PULL, REVOKE, HORIZON, END = 60, 100, 2000, 2400
RENEW, WTTL = 5, 15
STARTS = (50, 90, 130)
DURS = (20, 200, 1000, 3000)
FAULTS = ("crash A", "crash B", "link AC", "link BC", "link AB", "link AW", "link BW")


def run(faults, rule):
    def act(k, t):
        return any(f == k and s <= t < s + d for f, s, d in faults)
    def up(n, t):
        return not act(f"crash {n}", t)
    holds_role = {"A": True, "B": True}
    pulled_after = {"A": False, "B": False}
    confirmed = set()
    holder = {"A": True, "B": False}
    w_vote, w_seen = "A", 0
    p1 = p2 = two = none = 0
    for t in range(END):
        for n in "AB":
            if not up(n, t):
                holder[n] = False
                continue
            if t % PULL == 0 and not act(f"link {n}C", t):        # a successful pull (and report)
                if t >= REVOKE:
                    pulled_after[n] = True
                    if holds_role[n]:
                        holds_role[n] = False                       # the agent removes the role on applying
                    else:
                        confirmed.add(n)                            # the next report confirms the removal
            if t >= HORIZON:
                holds_role[n] = False
        # P1
        for n in "AB":
            if holds_role[n] and pulled_after[n]:
                p1 += 1
        # desk's leaver proof
        if rule == "per-edge" and confirmed:
            desk_removed = True
        else:
            desk_removed = confirmed >= {"A", "B"}
        if desk_removed and any(holds_role[n] and up(n, t) for n in "AB"):
            p2 += 1
        # address arbiter
        def reach(x, y, t=t):
            return up(x, t) and up(y, t) and not act(f"link {''.join(sorted(x + y))}", t)
        def reach_w(n, t=t):
            return up(n, t) and not act(f"link {n}W", t)
        if w_vote is not None and (not reach_w(w_vote) or t - w_seen > WTTL):
            if not reach_w(w_vote):
                if t - w_seen > WTTL:
                    w_vote = None
            else:
                w_seen = t
        if w_vote is not None and reach_w(w_vote):
            w_seen = t
        if t % RENEW == 0:
            for n in "AB":
                if not up(n, t):
                    continue
                other = "B" if n == "A" else "A"
                votes = 1
                if reach_w(n) and w_vote in (None, n):
                    votes += 1
                if reach(n, other) and not holder[other]:
                    votes += 1
                if votes >= 2:
                    if reach_w(n) and w_vote is None:
                        w_vote, w_seen = n, t
                    if reach_w(n) and w_vote not in (None, n):
                        continue                                    # W votes for the other: no majority with W
                    holder[n] = True
                else:
                    holder[n] = False
        hs = [n for n in "AB" if holder[n] and up(n, t)]
        if len(hs) > 1:
            two += 1
        could = any(up(n, t) and (reach_w(n) or reach(n, "B" if n == "A" else "A")) for n in "AB")
        if not hs and could:
            none += 1
    return p1, p2, two, none


def main():
    singles = [(f, s, d) for f in FAULTS for s in STARTS for d in DURS]
    combos = [(x,) for x in singles] + [c for c in itertools.combinations(singles, 2) if c[0][0] != c[1][0]]
    for rule in ("per-edge", "per-node"):
        agg = Counter(); worst = Counter(); ex = {}
        for c in combos:
            p1, p2, two, none = run(c, rule)
            for k, v in (("P1", p1), ("P2", p2), ("two holders", two), ("no holder", none)):
                if v:
                    agg[k] += 1
                    if v > worst[k]:
                        worst[k], ex[k] = v, c
        print(f"leaver-proof rule {rule}: {len(combos)} scenarios")
        for k in ("P1", "P2", "two holders", "no holder"):
            print(f"  {k}: {agg[k]} scenarios, worst {worst[k]} s" + (f"  e.g. {ex[k]}" if k in ex else ""))


if __name__ == "__main__":
    main()
