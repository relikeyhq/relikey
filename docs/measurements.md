# Measurements

Measured footprint of the edge components, replacing estimates in `model/components.yaml`. Each row names the
hardware, build and load; an arm64 run on reference hardware (R-10) is still open.

## 2026-10-23, amd64 lab box (8 dedicated vCPU, 32 GB, Ubuntu 24.04)

### Warpgate, upstream main a2570d76, `cargo build --release` (LTO)
Binary 95.0 MB. Run through Warpgate's own e2e harness (`start_wg`, recording on), SSH sessions through the bastion
to an OpenSSH target, each printing a 55-byte line every 0.1 s for 60 s.

| Phase | Peak RSS | RSS after | Sessions completed |
|---|---|---|---|
| idle (20 s after start) | 48.3 MB | - | - |
| 1 session | 53.8 MB | 53.9 MB | 1/1 |
| 10 concurrent | 67.1 MB | 67.1 MB | 10/10 |
| 25 concurrent | 85.2 MB | 85.2 MB | 25/25 |

- Memory grows about 1.5 MB per concurrent terminal session and is not returned after sessions end (allocator
  retention): budget the peak, not the idle.
- CPU: load average below 1 throughout on this box.
- Disk: the data directory grew 7.2 MB over 36 session-minutes (about 200 KB per session-minute). The per-phase growth
  (707, 368 and 81 KB per session-minute) also contains the SQLite database and its write-ahead log, so the recording
  share is closer to the lower figure. At this output rate a 90 MB recording store (switch profile) holds a few hundred
  terminal session-minutes. Not measured: graphical (RDP, VNC) recordings, which are far larger.

### lldap (`lldap/lldap:stable`, image digest sha256:2a8454b6...)
| Measure | Value |
|---|---|
| Image (uncompressed) | 26.5 MB |
| Idle | 2.7 MiB |
| Peak over 2,000 sequential LDAP simple binds | 55.1 MiB |
| After | 2.8 MiB |

Each bind runs a deliberately expensive password hash, so memory peaks under a stream of logins and drops back.

### Warpgate RDP sessions (same build and box)
Warpgate's own RDP test backend (xrdp) with screen activity added: a digital clock ticking once a second (close to an
idle HMI or appliance screen), and a terminal scrolling `ls -lR /usr` without pause (worst case for admin work).
FreeRDP client through Warpgate's RDP listener, RemoteFX, default 1024x768, 60 s per session, all sessions authorised.

| Load | Recording growth | Warpgate peak RSS |
|---|---|---|
| idle | - | 40.5 MB |
| 1 session, clock | 1.2 MB per minute | 68.5 MB |
| 1 session, scrolling | ~316 MB per minute (~5 MB/s) | 112.3 MB |
| 3 concurrent, scrolling | ~304 MB per session-minute | 258.5 MB |

- Why: the desktop recorder (`warpgate-core/src/recordings/desktop.rs`) composites screen updates and writes, at most
  every 1/30 s, a PNG of the changed region's bounding box. There is no video codec and no inter-frame compression,
  so a busy screen costs about 30 large PNGs a second; a mostly static screen costs almost nothing.
- Memory: about 70 MB per busy RDP session (versus about 1.5 MB per terminal session).
- Frame rate (upstream PR #2784, `desktop_recording_frame_rate`), counted in the recording file itself: at the default
  30 a 65 s busy session wrote 1,493 delta frames (~23 fps achieved) and 145 keyframes, 342 MB; at 5 it wrote 305 delta
  frames and 32 keyframes, 77 MB - about 4.5x smaller. Method note: growth of the whole data directory is not a reliable
  per-session measure (it also catches writes finishing from the previous session); count the recording file.

### Not measured
The proxy under load (idle: below), the edge host itself, Warpgate on arm64 and armv7, VNC, Warpgate with HTTP/web
sessions. The edge agent: below.

## 2026-10-25, the edge agent (d4c15f6)

**Package.** One static binary, release flags (`-trimpath -s -w`); the image is `scratch` plus the binary and two empty
directories, so the image is the binary.

| Build | linux/amd64 | linux/arm64 | linux/arm v7 | gzip (amd64) |
|---|---|---|---|---|
| a0d287e (2026-10-23, first soaked build) | 7.36 MB | 6.82 MB | 7.27 MB | 3.09 MB |
| 653e936 (2026-10-24, before full-stack run 2) | 9.33 MB | 8.72 MB | 9.04 MB | 3.82 MB |
| d4c15f6 (2026-10-25: governed roles, events, long-poll) | 9.37 MB | 8.72 MB | 9.11 MB | 3.83 MB |
| d4c15f6 without the status page's templates (experiment) | 7.65 MB | - | 7.47 MB | - |

- The 2 MB of growth came almost entirely with the status page (`page.go`): `html/template` and `text/template` call
  methods by reflection, so the linker keeps every exported method in the program. Measured: 1.72 MB on amd64 and 1.64
  MB on armv7 (18% of the binary). Today's work (finding 8, events, long-poll) added 40-70 KB.
- Shipped code grew from 2,975 to 5,122 lines (tests, fakes, the soak and the test emitter: 2,269 to 4,318). The binary
  depends on one module outside the standard library (`golang.org/x/sys`), 221 packages in all.

**Runtime.** `relikey-soak`, 8 minutes on Linux (WSL2, x86_64), the long-poll on, 20 users with lease churn and 16
injected fault windows (desk down, desk replaying an old bundle, Warpgate down, Warpgate 30% errors): 246 grants, 12,878
Warpgate requests, 155 desk answers; safety 0 violations, liveness 0 misses, pass.

| | This run | Earlier soaks (2026-10-23) |
|---|---|---|
| Peak RSS | 16.9 MB | 14-15 MB |
| Growth, second to last quarter | RSS 0.0%, heap -7.6%, goroutines and descriptors 0 | RSS -3% to +1% |
| Peak Go heap in use | 3.3 MB (heap reserved 12 MB) | - |
| Goroutines | 11 | 8 |
| Open descriptors | 11 | - |
| State directory | 37 KB | - |
| Log on stdout (events included) | 830 KB in 8 minutes under soak churn (893 events) | - |

- The three extra goroutines are the long-poll's fetcher and its HTTP connection.
- The footprint model's estimate for the agent (30 MB, switch profile) holds with margin.
- Log volume under real load is far lower than under the soak's churn, but stdout grows without bound: the container
  runtime must rotate it (docker's default `json-file` driver does not unless `max-size` is set).

Not measured: CPU, the armv7 and arm64 binaries on real hardware (qemu only so far), a 24-hour run.

Nice to have (operator, 2026-10-25; fleet management first): render the status page without templates (about 1.7 MB
back); rotate the container's stdout (`logging` options in the edge compose file).

## 2026-10, the edge proxy (pinned Caddy, 2.11.7-alpine)

The edge's filtering proxy ships as the pinned Caddy image (`deploy/edge/compose.yaml`, service `front`) rather than
the minimal purpose-built proxy the model first estimated at 15 MB. A first measurement on amd64:

| | Value |
|---|---|
| Resident memory, idle | about 50 MB |
| Image | 67 MB |

Not measured: the proxy under a session load, arm64 and armv7, real hardware (R-10). The model now carries these
figures (`model/components.yaml`, proxy).

## What it changes
The switch profile allows 256 MB of memory for the edge (512 MB x 0.5). With the measured peaks - Warpgate 85 MB at
25 sessions, lldap 55 MB under a login burst, the pinned Caddy proxy 50 MB idle - plus the estimates for the host (60)
and agent (30), the edge needs about 282 MB (peaks rounded up): it does **not** fit, by about 26 MB. With the 15 MB
first estimated for a minimal proxy it fitted with about 9 MB to spare. The model records this as a known gap on the
switch profile (`model/footprint.yaml`, issue #62) rather than hiding it; the remedy - tuning Caddy, a smaller proxy,
or a revised profile - is chosen in 0.3.0 after measuring on the reference hardware. The small-board profile (1 GB)
has ample room.

Graphical sessions settle it: one busy RDP session alone needs about 112 MB for Warpgate, so the switch profile cannot
carry graphical targets at all (the edge would need about 308 MB of its 256 MB), and its 90 MB recording store holds
under 20 seconds of a busy screen. On the small-board profile (512 MB budget) about four busy RDP sessions fit, and its
2 GB store holds about six minutes of busy-screen recording offline. Online, every busy RDP session needs about 5 MB/s
of upload to the evidence store. A lower recording frame rate in Warpgate would cut this several-fold (upstream U-11).
