# The demo: ReliKey against stand-ins

One command shows what ReliKey does, with nothing installed but Go:

    cd agent
    go run ./cmd/relikey-demo

It runs the real edge agent loop against stand-ins for KeyClerk's edge routes, Warpgate's admin API and the identity
broker (the same stand-ins the agent's tests use, `agent/internal/fakes`), opens a page in your browser and plays a
short story:

1. Ann signs in at the identity broker.
2. KeyClerk grants her a lease: role `plc-operator` on target `plc` for one hour, signed into the edge's next bundle.
3. The agent verifies the bundle against its pinned keys and the account appears on the bastion with that role.
4. Ann opens a session through the bastion.
5. The lease is revoked: the agent closes her session and removes her account.
6. Bob gets a short lease, then the edge loses its network (the desk answers nothing).
7. Bob's lease still ends on time: the agent ends it from the bundle it had already verified, with no one to ask.

The page shows each step as it happens, with the bastion's accounts and open sessions beside it. Press Ctrl-C in the
terminal to stop.

## What it is, and what it is not
- **A demo.** Every screen says so. It is a separate command (`agent/cmd/relikey-demo`) and never part of a release:
  `build.py release` builds the agent alone.
- **No real systems or secrets.** The enrolment key, the desk's bundle key, the officer's key and the bastion token are
  generated at start and live only in memory and a temporary directory; nothing is read from the network or the disk.
- **Loopback only.** The stand-ins and the page listen on 127.0.0.1; `-addr` refuses any other address.
- **Leaves nothing behind.** The temporary state directory is removed when the story ends or on Ctrl-C.
- **Not a lab.** The stand-ins follow the routes and status codes the agent uses; they are not KeyClerk, Warpgate or
  an OIDC provider. The broker stand-in signs a person in without a password, only to start the story. For the real
  composition, see the quickstart in the [README](../README.md).

## Options

| Flag | Default | What it does |
|---|---|---|
| `-headless` | off | No page: one JSON line per step on stdout; exit 1 if a step does not happen within 20 s |
| `-addr` | `127.0.0.1:0` | The page's loopback address (port 0 picks a free one) |
| `-no-open` | off | Print the page's address instead of opening a browser |
| `-pace` | `2s` | Pause after each step on the page, so you can follow it |
| `-wait` | off | Start the story when the page is first opened, not at start (for a forwarded port) |

## In a Codespace
The README's Codespaces badge opens this repository with `.devcontainer/devcontainer.json`: the Go image pinned by
digest, the demo built on create and started on attach with `-addr 127.0.0.1:8080 -no-open -wait`. Codespaces forwards
the port privately to you and opens the page in the editor's preview; the story starts when the page loads. Nothing
else runs in the Codespace and no secrets are used. Stop it with Ctrl-C in the terminal; delete the Codespace when you
are done (your GitHub account's Codespaces quota applies).

## In CI
`go test ./cmd/relikey-demo` plays the whole story headless and fails unless every step happens in order and the
temporary directory is gone afterwards; the agent gate (`python agent/build.py check`) runs it on every push, and the
CI workflow also runs `go run ./cmd/relikey-demo -headless`. A run takes about ten seconds.
