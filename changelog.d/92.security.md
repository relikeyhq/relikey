- The SBOM tool's `golang.org/x/crypto`, `x/net` and `x/text` are current, and each Go module's `go` line names
  Go 1.27.3, the release the code is built with, so dependency scanners no longer report advisories it already
  fixes. govulncheck finds nothing reachable in the agent or the fleet service, before and after.
