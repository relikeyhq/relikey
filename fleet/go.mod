module relikey/fleet

go 1.27

toolchain go1.27.3

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/go-jose/go-jose/v4 v4.1.6
	golang.org/x/oauth2 v0.37.0
	relikey/agent v0.0.0
)

require github.com/x448/float16 v0.8.4 // indirect

replace relikey/agent => ../agent
