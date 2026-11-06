"""Timed model of the two-node edge election (decision 0028 draft 1), checked over every fault scenario in a small scope.

Nodes A (primary at t=0) and B (standby), monitor M. Time in seconds. One or two faults per scenario, each with a
start and a duration, from: a node's crash, a node's freeze (process pause: keeper and PostgreSQL stop, then resume
believing what they believed), a whole-machine freeze (the kernel stops too: softdog stops with it), the A-B link,
the A-M link, the B-M link. pg_auto_failover's rules as documented:
  - the monitor promotes the standby once the primary has been unhealthy for PROMOTE_WAIT and the standby is healthy
    to it and caught up (a standby cut from the primary is still caught up when nothing was written meanwhile);
  - a primary that can reach neither the monitor nor its standby for PARTITION_TIMEOUT stops (self-fence);
  - a demoted node never comes back as primary on its own.
Watchdog (decision 0028 point 1): a node whose keeper has not reported for WATCHDOG is reset (it reboots as standby).
A softdog runs in the kernel: a whole-machine freeze stops it too; a hardware watchdog does not stop.

Invariants:
  I1 one writer: at no second are two nodes writable primaries.
  I2 availability (reported, not an invariant): seconds with no writable primary while a healthy node and the monitor
     could reach each other.
Usage: python hamodel.py [--no-watchdog] [--softdog]
"""
import itertools, sys
from collections import Counter

PROMOTE_WAIT, PARTITION_TIMEOUT, HEALTH_PERIOD = 90, 20, 5
WATCHDOG = 60                      # < PROMOTE_WAIT
HORIZON = 400
STARTS = (10, 50)
DURATIONS = (5, 30, 85, 100, 300)
FAULTS = ("crash A", "crash B", "freeze A", "freeze B", "machine A", "machine B", "link AB", "link AM", "link BM")


def run(faults, watchdog="hardware"):
    def active(kind, t):
        return any(k == kind and s <= t < s + d for k, s, d in faults)

    role = {"A": "primary", "B": "standby"}
    up = {"A": True, "B": True}
    believes_primary = {"A": True, "B": False}      # what a frozen node wakes up believing
    unhealthy_since = None
    isolated_since = {"A": None, "B": None}
    silent_since = {"A": None, "B": None}           # keeper not reporting (frozen)
    writes_on = Counter()
    monitor_primary = "A"
    two_writers, down = [], 0
    for t in range(HORIZON):
        for n in "AB":
            crashed = active(f"crash {n}", t)
            frozen = active(f"freeze {n}", t) or active(f"machine {n}", t)
            if crashed:
                up[n] = False
                role[n] = "down"
                continue
            if not up[n]:                               # back from a crash: rejoins as standby
                up[n] = True
                role[n] = "standby"
                believes_primary[n] = False
            # watchdog: a frozen keeper for WATCHDOG seconds resets the node, unless the watchdog is frozen too
            if frozen:
                silent_since[n] = silent_since[n] if silent_since[n] is not None else t
                wd_runs = watchdog == "hardware" or (watchdog == "softdog" and not active(f"machine {n}", t))
                if watchdog and wd_runs and t - silent_since[n] >= WATCHDOG:
                    role[n] = "down"                    # reset: comes back as standby when the freeze ends
                    believes_primary[n] = False
                    up[n] = False
                continue
            silent_since[n] = None
            if role[n] == "frozen-wake":
                role[n] = "primary" if believes_primary[n] else "standby"

        def reach(x, y):
            if x == "M" or y == "M":
                n = x if y == "M" else y
                return not active(f"link {n}M", t)
            return not active("link AB", t)

        def healthy(n):                                 # running, not frozen, not crashed
            return up[n] and not active(f"freeze {n}", t) and not active(f"machine {n}", t) and role[n] != "down"

        # a node acting as primary that reaches the monitor learns at its next health check who the monitor's
        # primary is, and steps down when it is not that node
        for n in "AB":
            if role[n] == "primary" and healthy(n) and reach(n, "M") and monitor_primary != n and t % HEALTH_PERIOD == 0:
                role[n] = "standby"
                believes_primary[n] = False
        prim = [n for n in "AB" if role[n] == "primary"]
        # a primary that reaches neither the monitor nor the standby self-fences after PARTITION_TIMEOUT
        for n in prim:
            other = "B" if n == "A" else "A"
            alone = healthy(n) and not reach(n, "M") and not (reach(n, other) and healthy(other) and role[other] == "standby")
            # pg_auto_failover counts a standby connected to its replication slot: a peer that became primary does not count
            if alone:
                isolated_since[n] = isolated_since[n] if isolated_since[n] is not None else t
                if t - isolated_since[n] >= PARTITION_TIMEOUT:
                    role[n] = "standby"
                    believes_primary[n] = False
            else:
                isolated_since[n] = None
        # the monitor promotes the standby after PROMOTE_WAIT of an unhealthy (to it) primary
        prim = [n for n in "AB" if role[n] == "primary"]
        cur = prim[0] if prim else None
        if cur is None or not (healthy(cur) and reach(cur, "M")):
            unhealthy_since = unhealthy_since if unhealthy_since is not None else t
            if t - unhealthy_since >= PROMOTE_WAIT:
                for n in "AB":
                    if n != cur and healthy(n) and reach(n, "M") and role[n] == "standby":
                        if cur is not None:
                            # the monitor marks the old primary demoted; a frozen one does not know yet
                            believes_primary[cur] = believes_primary[cur] and not healthy(cur)
                            if healthy(cur):
                                role[cur] = "standby"   # it hears the monitor's state at its next contact
                            else:
                                role[cur] = "frozen-wake" if up[cur] else role[cur]
                        role[n] = "primary"
                        believes_primary[n] = True
                        monitor_primary = n
                        unhealthy_since = None
                        break
        else:
            unhealthy_since = None
        writable = [n for n in "AB" if role[n] == "primary" and healthy(n)]
        if len(writable) > 1:
            two_writers.append(t)
        if not writable and any(healthy(n) and reach(n, "M") for n in "AB"):
            down += 1
    return two_writers, down


def main():
    wd = "hardware"
    if "--no-watchdog" in sys.argv:
        wd = None
    if "--softdog" in sys.argv:
        wd = "softdog"
    bad, worst_down, n = [], (0, None), 0
    longest = [0]
    singles = [(f, s, d) for f in FAULTS for s in STARTS for d in DURATIONS]
    for k in (1, 2):
        for combo in itertools.combinations(singles, k):
            if k == 2 and combo[0][0] == combo[1][0]:
                continue
            n += 1
            two, down = run(combo, wd)
            if two:
                bad.append((combo, two[0], len(two)))
                longest[0] = max(longest[0], len(two))
            if down > worst_down[0]:
                worst_down = (down, combo)
    print(f"watchdog={wd}: {n} scenarios; two writable primaries in {len(bad)}, longest {longest[0]} s")
    by_kind = Counter(tuple(sorted({f for f, _, _ in c})) for c, _, _ in bad)
    for kinds, cnt in by_kind.most_common(8):
        print(f"  {cnt:4d}  {', '.join(kinds)}")
    for combo, t, secs in bad[:3]:
        print(f"  e.g. {combo}: from t={t}, {secs} s")
    print(f"  worst outage with a healthy node and the monitor in reach: {worst_down[0]} s, {worst_down[1]}")


if __name__ == "__main__":
    main()
