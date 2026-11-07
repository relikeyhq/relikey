// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"relikey/agent/internal/kcedge"
)

// anchor is a person's anchor at the desk: provider-prefixed (op:, idp:, ext:, ...), as KeyClerk names people.
var anchor = regexp.MustCompile(`^[a-z][a-z0-9-]*:\S+$`)

// officerNote warns when a statement names its officer by something other than an anchor: the desk names the edge's
// officer by anchor and refuses such a statement as another record's ("officer differ"; walk 2026-11-06, F17). A
// warning, not a refusal: the anchor's form is the desk's to define.
func officerNote(officer any) string {
	s, _ := officer.(string)
	if anchor.MatchString(s) {
		return ""
	}
	return fmt.Sprintf("note: the statement names the officer %q, which is not an anchor (op:..., as the desk's People "+
		"page shows it); the desk names the edge's officer by anchor and will refuse this statement (officer differ). "+
		"Ask the officer for a statement made with --officer <their anchor>", s)
}

// Enrolment on the edge's side (KeyClerk 0.23.0, interface section 2): the officer and
// each node sign one kc-edge-officer-v2 statement over the same bytes, and each node
// has a P-256 unlock key for the phoned unlock (kc-unlock-v2; in its TPM where it has
// one, a software key here).

func enrolmentKey(path string) (ed25519.PrivateKey, error) {
	seedHex, err := readSecret(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, badSeed(path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// badSeed says why an enrolment key file is refused and what completes the task: the key edges and the desk know
// is restored, never replaced in passing.
func badSeed(path string) error {
	return fmt.Errorf("%s: not an Ed25519 seed of 64 hex characters, so the agent cannot sign as this edge; restore "+
		"the enrolment key from the edge's backup (a new key needs the edge enrolled again at the desk)", path)
}

func readStatement(path string) (kcedge.MultiSigned, kcedge.Object, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return kcedge.MultiSigned{}, nil, err
	}
	var m kcedge.MultiSigned
	if err := json.Unmarshal(b, &m, json.RejectUnknownMembers(true)); err != nil {
		return kcedge.MultiSigned{}, nil, fmt.Errorf("%s is not a multi-signed statement: %w", path, err)
	}
	v, err := kcedge.Parse(b)
	if err != nil {
		return kcedge.MultiSigned{}, nil, err
	}
	var signers []string
	for _, s := range m.Signatures {
		signers = append(signers, s.Key)
	}
	// What it says, checked as signed by whoever signed it so far (the same bytes for all).
	says, err := kcedge.UnsealMulti(v, signers, kcedge.OfficerFormat)
	if err != nil {
		return kcedge.MultiSigned{}, nil, err
	}
	return m, says, nil
}

// statementShow prints what a statement says and who has signed it, before anyone
// signs: the edge, the officer, the purpose and every node with its keys.
func statementShow(args []string) error {
	fs := flag.NewFlagSet("statement", flag.ExitOnError)
	in := fs.String("in", "", "the statement file (kc-edge-officer-v2)")
	_ = fs.Parse(args)
	m, says, err := readStatement(*in)
	if err != nil {
		return err
	}
	fmt.Printf("statement %s for edge %v, purpose %v\nofficer %v key %v\n", kcedge.OfficerFormat, says["edge"], says["purpose"],
		says["officer"], says["officer_key"])
	if note := officerNote(says["officer"]); note != "" {
		fmt.Println(note)
	}
	nodes, _ := says["nodes"].([]kcedge.Value)
	for i, n := range nodes {
		o, _ := n.(kcedge.Object)
		fmt.Printf("node %d: enrolment key %v (key id %s), unlock key %v, tpm %v\n", i+1, o["enrolment_key"],
			kcedge.KeyID(fmt.Sprint(o["enrolment_key"])), o["unlock_key"], o["tpm"])
	}
	for _, s := range m.Signatures {
		fmt.Printf("signed by %s (key id %s)\n", s.Key, s.KeyID)
	}
	return nil
}

// cosign adds this node's signature to the statement after checking that the statement
// names this node's enrolment key (and its unlock key when one is given).
func cosign(args []string) error {
	fs := flag.NewFlagSet("cosign", flag.ExitOnError)
	in := fs.String("in", "", "the statement file")
	out := fs.String("out", "", "file for the statement with this node's signature (must not exist)")
	keyFile := fs.String("key", "", "this node's enrolment key file (default: enrolment_key_file in the agent's configuration)")
	cfgPath := fs.String("config", "/etc/relikey/agent.json", "the agent's configuration, for its enrolment key when -key is not given")
	unlockFile := fs.String("unlock-key", "", "this node's software unlock key file (optional: checks the statement names it)")
	_ = fs.Parse(args)
	if *in == "" || *out == "" {
		return errors.New("usage: relikey-agent cosign -in STATEMENT -out FILE [-key ENROLMENT_KEY] [-unlock-key FILE]")
	}
	if *keyFile == "" { // the key the agent itself uses, so a moved key (#134: keys/enrolment.key) is still found (walk F18)
		c, err := loadConfig(*cfgPath)
		if err != nil {
			return fmt.Errorf("no -key given and the agent's configuration cannot be read (%w): give -key, this node's "+
				"enrolment key file", err)
		}
		*keyFile = c.EnrolmentKeyFile
	}
	key, err := enrolmentKey(*keyFile)
	if err != nil {
		return err
	}
	m, says, err := readStatement(*in)
	if err != nil {
		return err
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	var mine kcedge.Object
	nodes, _ := says["nodes"].([]kcedge.Value)
	for _, n := range nodes {
		if o, _ := n.(kcedge.Object); o["enrolment_key"] == pub {
			mine = o
		}
	}
	if mine == nil {
		return fmt.Errorf("the statement does not name this node's enrolment key %s: not signed. Check that -key is "+
			"this node's enrolment key, or ask the officer for the statement that names it", pub)
	}
	if *unlockFile != "" {
		uk, err := unlockKey(*unlockFile)
		if err != nil {
			return err
		}
		if mine["unlock_key"] != kcedge.UnlockPublicString(uk) {
			return errors.New("the statement names another unlock key for this node: not signed. Check that " +
				"-unlock-key is the one made for this node, or ask the officer for a statement that names it")
		}
	}
	if note := officerNote(says["officer"]); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	signed, err := kcedge.Cosign(m, key)
	if err != nil {
		return err
	}
	b, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	fmt.Printf("signed as node %s for edge %v\n", kcedge.KeyID(pub), says["edge"])
	return f.Close()
}

func unlockKey(path string) (*ecdh.PrivateKey, error) {
	s, err := readSecret(path)
	if err != nil {
		return nil, err
	}
	return kcedge.UnlockPrivate(s)
}

// unlockKeygen makes a software P-256 unlock key, for a node without a TPM.
func unlockKeygen(args []string) error {
	fs := flag.NewFlagSet("unlock-keygen", flag.ExitOnError)
	out := fs.String("out", "", "file for the new unlock key (must not exist)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("usage: relikey-agent unlock-keygen -out FILE")
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(k.Bytes()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("unlock key %s (%s)\n", kcedge.UnlockPublicString(k), kcedge.UnlockContext)
	return nil
}

// unlockCode computes the code an approver reads over the phone, so the node can compare
// it with what the person on site types.
func unlockCode(args []string) error {
	fs := flag.NewFlagSet("unlock-code", flag.ExitOnError)
	keyFile := fs.String("unlock-key", "", "this node's software unlock key file")
	enrolFile := fs.String("key", "", "this node's enrolment key file (its key id names the node)")
	desk := fs.String("desk-unlock-key", "", "the desk's unlock key from GET /edge-key (pinned)")
	edge := fs.String("edge", "", "the edge id")
	person := fs.String("person", "", "the person")
	fingerprint := fs.String("fingerprint", "", "the hardware key's fingerprint")
	target := fs.String("target", "", "the target")
	nonce := fs.String("nonce", "", "the nonce shown")
	minutes := fs.Int("minutes", 0, "the minutes asked for")
	_ = fs.Parse(args)
	uk, err := unlockKey(*keyFile)
	if err != nil {
		return err
	}
	ek, err := enrolmentKey(*enrolFile)
	if err != nil {
		return err
	}
	node := kcedge.KeyID(hex.EncodeToString(ek.Public().(ed25519.PublicKey)))
	secret, err := kcedge.UnlockSecret(uk, strings.TrimSpace(*desk), kcedge.UnlockPublicString(uk), *edge, node)
	if err != nil {
		return err
	}
	code, err := kcedge.UnlockCode(secret, *edge, node, *person, *fingerprint, *target, *nonce, *minutes)
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}
