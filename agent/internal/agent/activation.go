// SPDX-License-Identifier: EUPL-1.2

package agent

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"relikey/agent/internal/keyclerk"
)

// ActivationName is the file in the state directory that says how this node became active (decision 0028: a spare
// promoted by hand with the site key's statement; edge protocol 1.5 section 7.3).
const ActivationName = "activation.json"

// ReadActivation reads the activation file; a missing file is no activation (nil, nil).
func ReadActivation(path string) (*keyclerk.Activation, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a keyclerk.Activation
	if err := json.Unmarshal(b, &a, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if a.By != "witness" && a.By != "local_witness" && a.By != "break_glass" {
		return nil, fmt.Errorf("%s: by %q is witness, local_witness or break_glass", path, a.By)
	}
	if (a.By == "break_glass") != (len(a.Statement) > 0) {
		return nil, fmt.Errorf("%s: a break-glass activation carries the site key's promotion statement, and only it does", path)
	}
	return &a, nil
}

// WriteActivation replaces the activation file whole: a temporary file in the same directory, fsynced, then one
// rename, so a crash leaves the old activation or the new one, never half of either.
func WriteActivation(path string, a keyclerk.Activation) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".activation-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// activation is what the report carries: the file's activation, or none. A file that cannot be read is said in the
// log and left out of the report (the desk then records no activation), never sent half-read.
func (a *Agent) activation() *keyclerk.Activation {
	if a.ActivationFile == "" {
		return nil
	}
	act, err := ReadActivation(a.ActivationFile)
	if err != nil {
		a.Log.Warn("this node's activation cannot be read and is not reported", "err", err,
			"next", "run relikey-agent promote again with the site key's promotion statement")
		return nil
	}
	return act
}
