# Warpgate on Windows: what a port needs

Evidence for the Windows direction (decision 0014, the sign-in gateway; a future decision 0015, the Windows engine) and
for the upstream ask (warp-tech/warpgate discussion #2813, 2026-10-24). This records what an actual Windows build of
Warpgate hits, not a guess.

## Why this matters
Many legacy production estates are Windows server farms. Their admins would sooner run a Windows service than stand up
a Linux VM, so a native Windows Warpgate would remove an adoption objection (BIRDSEYE 2026-10-24 route D). ReliKey's
edge agent already cross-compiles for Windows; the open question was Warpgate itself, whose answer this file holds.

## Method
On a throwaway Linux build box (Ubuntu), upstream main a2570d7:
1. `cargo check --target x86_64-pc-windows-gnu` to find the first failing layer.
2. `cargo build --release --target x86_64-pc-windows-gnu` with the Unix-only spots stubbed (box-local, never committed,
   never upstream) to see every layer, then run the `.exe` under Wine to prove it links and starts.

The stubs are a scratch script (`scratchpad .../winstub.py`): they are not the port. A real port cfg-gates each spot
with a proper Windows implementation; the stubs exist only to reach the link and the run.

## The vendored crates are fine
`cargo check --keep-going` compiled every dependency that does not sit above `warpgate-core`, the vendored RDP/VNC/
Kerberos stack among them (IronRDP, sspi, picky, vnc-rs). None failed to cross-compile. So the heavy protocol
libraries are not the obstacle; only Warpgate's own crates assume Unix.

## The Unix-only spots in Warpgate's own crates
Found by building, in the order the compiler hits them. A static grep had found the first four; building found the
last two, which is the point of building.

| # | File | What it is | Port approach |
|---|---|---|---|
| 1 | `warpgate-common/src/helpers/fs.rs` | Tightens file permissions via Unix mode bits (`PermissionsExt`, `MetadataExt`, `nix::unistd`) | Windows: tighten via ACLs; or no-op with a warning in a first cut |
| 2 | `warpgate-core/src/logging/socket.rs` | Forwards logs over a Unix datagram socket (`tokio::net::UnixDatagram`) | Windows: no-op log layer first; a named pipe or UDP later |
| 3 | `warpgate/src/commands/run.rs` | `sd_notify` (systemd) and `tokio::signal::unix` SIGINT/SIGTERM | sd_notify already `cfg(target_os="linux")`; use `tokio::signal::windows::{ctrl_c, ctrl_close}`; run as a Windows service |
| 4 | `warpgate/src/commands/internal_install_files.rs` (test) | A test uses `std::os::unix` symlink/mode | `cfg(unix)` the test; `cargo build` ignores it anyway |
| 5 | `warpgate-protocol-ssh/src/server/mod.rs` | Clones the client socket fd (`std::os::fd::AsFd`) to call `shutdown(2)` from outside russh when a write hangs | **Real fix, not a stub:** Windows `std::os::windows::io::AsSocket::as_socket().try_clone_to_owned()`; `TcpStream::shutdown(Shutdown::Both)` is already cross-platform |
| 6 | `warpgate/src/commands/setup.rs` | `default_data_path` is defined for linux and macos only | add `#[cfg(windows)] let default_data_path = "C:\\ProgramData\\warpgate";` |

Spot 5 is the only non-mechanical one, and even it has a clean Windows equivalent in std. Everything else is a cfg-gate
plus a small Windows branch. No architectural blocker surfaced.

## Proposed upstream shape (small, separate PRs, per discussion #2813)
1. cfg-gate spots 1 to 6 (ACL checks, ctrl_c/service-stop, log forwarding Unix-only for now, the `as_socket` clone, a
   Windows data path).
2. Run as a Windows service.
3. A Windows CI job and a release artifact.

## Status (2026-10-24): it links and runs
With the six spots stubbed, `cargo build --release --target x86_64-pc-windows-gnu` produced `warpgate.exe`
(about 96 MB). Run under Wine 9.0 on the build box:
- `warpgate.exe --help` prints its usage (the binary loads and runs).
- `warpgate.exe ... unattended-setup ...` exited 0 and wrote `warpgate.yaml`, `db.sqlite3` and the TLS cert/key into
  the Windows data path.
- `warpgate.exe ... run` bound both listeners and started serving:
  `Binding listener name="SSH" endpoint=[::]:2223`, `Binding listener name="HTTP" endpoint=[::]:8890`, and the HTTP
  protocol initialised. So a Windows build sets up and binds its ports; it is not merely a successful compile.

Caveats: `--version` exited 2 under Wine (cosmetic; `--help` works); the run was a 12 s bind check, not a session test;
Wine is not Windows, so a real Windows host is still the proof that matters; and the six spots were stubbed, not
ported. But no architectural blocker exists between upstream Warpgate and a Windows build.

Not done, by design: a correct (non-stub) implementation of each spot, a Windows service wrapper, Windows CI, and a
real SSH/RDP session on a true Windows host.

## Functional test (2026-10-24, Wine 9.0 on the lab box)

Beyond the bind check, the Windows `.exe` (vanilla upstream `v0.30.0-1-ga2570d76`, the six spots stubbed) was
exercised end to end:

- `version` and `check` work (`check` -> "No problems found"). `--version` still exits 2 (cosmetic; use `version`).
- `unattended-setup` generated a TLS certificate, SSH host keys, the SQLite database, the admin user and a 1931-byte
  config. So certificate generation, key generation, SQLite init and config writing all work on Windows.
- `run` bound both listeners (SSH and HTTPS).
- HTTPS admin API: `GET /@warpgate/api/info` returned real JSON; a `POST /@warpgate/api/auth/login` with the admin
  password returned **201** with an `"Authenticated"` audit event, the session then read `/@warpgate/admin/api/users`
  and got the real user list, and a wrong password returned **401** with the login-protection service recording the
  attempt. The HTTP/TLS (rustls) stack, the admin API, the SQLite credential store and session issuance all work.
- SSH bastion: the server accepts connections and runs the full auth pipeline (keyboard-interactive and password,
  credential verification, login-protection) - proven by the server logs, not just a port bind.

So a Windows build is functional, not merely a successful compile: it sets up, serves its admin API under TLS,
verifies credentials against its database, issues sessions, and runs the SSH auth pipeline.

Two rough edges found: `unattended-setup` requires `--admin-password`/`WARPGATE_ADMIN_PASSWORD` (by design), and it
does not create `--data-path` if it is absent, failing with a misleading "File not found (os error 2)" - verify
against Linux before raising upstream. Still not done: a full SSH/RDP session to a real target on a true Windows host,
a Windows service wrapper, Windows CI, and non-stub implementations of the six spots.

## Changelog
- 2026-10-24: created from the lab-box Windows build investigation.
- 2026-10-24: functional test added (setup, listeners, admin API auth loop, SSH auth pipeline under Wine).
