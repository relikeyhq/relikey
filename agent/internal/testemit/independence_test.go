// SPDX-License-Identifier: EUPL-1.2

package testemit

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The emitter is only a second opinion while it shares no code with what it tests: no import of the agent's
// verifier, its fakes or anything KeyClerk's (decision 0017 point 6).
func TestTheEmitterSharesNoCodeWithTheVerifier(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "emit.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(path, "relikey/") || strings.Contains(strings.ToLower(path), "keyclerk") {
			t.Fatalf("emit.go imports %s: the second emitter must be written from the published format alone", path)
		}
	}
}
