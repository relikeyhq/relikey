// SPDX-License-Identifier: EUPL-1.2

// Package enrol is enrolment into the fleet (decision 0026 points 15, 24, 30, 32, 33): a slot opened in the GUI, a
// one-time code naming the fleet, the edge's key presented with proof of the code's secret and of the key itself,
// and activation by one officer's passkey over a bound statement. Pure: no storage, no HTTP.
package enrol

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"relikey/fleet/internal/registry"
)

const (
	SlotLife       = 24 * time.Hour
	MaxBatch       = 10  // slots one activation may carry (point 24)
	MaxOpen        = 200 // open slots per fleet
	MaxOpenPerUser = 20  // open slots per operator
	MinTyped       = 16  // base32 characters typed from the edge's screen: 80 bits (point 24)
	MaxRefused     = 3   // refused presentations that close a slot: a code is not guessed at, it is reissued
	CodePrefix     = "relikey-enrol-v1:"
	presentContext = "relikey-enrol-present-v1"
)

// Kind is what a slot admits: a leaf edge, a relay, or a site fleet (whose admission the approver reads themselves).
type Kind string

const (
	Edge  Kind = "edge"
	Relay Kind = "relay"
	Site  Kind = "site"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Slot is one admission in progress.
type Slot struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Kind       Kind      `json:"kind"`
	Profile    string    `json:"profile"`
	OpenedBy   string    `json:"opened_by"` // the broker subject of the GUI session (point 24)
	OpenedAt   time.Time `json:"opened_at"`
	Expires    time.Time `json:"expires"`
	SecretHash string    `json:"secret_hash"`   // hex sha256 of the single-use secret: the commitment
	Key        string    `json:"key,omitempty"` // the presented public key, hex, once presented
	Presented  time.Time `json:"presented,omitzero"`
	Source     string    `json:"source,omitempty"` // the address the presentation came from, shown to the approver
	Active     bool      `json:"active"`
	Refused    []string  `json:"refused,omitempty"` // what was refused for this slot: shown and alarmed, never silent
}

// Code is what the installer takes: it names the fleet, its pin and anchor, the slot and the secret.
type Code struct {
	Fleet  string `json:"fleet"`
	URL    string `json:"url"`    // the fleet's enrolment route, https
	Pin    string `json:"pin"`    // the fleet's long-term key or CA, hex sha256 (point 27)
	Anchor string `json:"anchor"` // the anchor registry's hash (point 30): a re-anchored fleet is another fleet
	Slot   string `json:"slot"`
	Secret string `json:"secret"` // base64url, single use
}

func (c Code) String() string {
	b, _ := json.Marshal(c, json.Deterministic(true))
	return CodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseCode reads a code as the installer receives it (QR or USB, point 24).
func ParseCode(s string) (Code, error) {
	var c Code
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), CodePrefix))
	if !strings.HasPrefix(strings.TrimSpace(s), CodePrefix) || err != nil || json.Unmarshal(raw, &c) != nil {
		return c, errors.New("not a ReliKey enrolment code")
	}
	if !strings.HasPrefix(c.URL, "https://") || len(c.Pin) != 64 || len(c.Anchor) != 64 || c.Slot == "" || c.Secret == "" {
		return c, errors.New("the enrolment code lacks the fleet's address, pin, anchor, slot or secret")
	}
	return c, nil
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Open makes a slot and its code. open are the slots not yet active or expired, to enforce the caps.
func Open(fleet, url, pin, anchor, name string, kind Kind, profile, by string, open []Slot, now time.Time) (Slot, Code, error) {
	if !nameRE.MatchString(name) {
		return Slot{}, Code{}, errors.New("a name: lower-case letters, digits and hyphens")
	}
	if kind != Edge && kind != Relay && kind != Site {
		return Slot{}, Code{}, errors.New("a slot admits an edge, a relay or a site fleet")
	}
	live, mine := 0, 0
	for _, s := range open {
		if !s.Active && now.Before(s.Expires) {
			live++
			if s.OpenedBy == by {
				mine++
			}
			if s.Name == name {
				return Slot{}, Code{}, fmt.Errorf("a slot for %s is already open", name)
			}
		}
	}
	if live >= MaxOpen || mine >= MaxOpenPerUser {
		return Slot{}, Code{}, fmt.Errorf("too many open slots (%d in the fleet, %d of yours): close or let some expire", live, mine)
	}
	secret := random(32)
	s := Slot{ID: random(12), Name: name, Kind: kind, Profile: profile, OpenedBy: by, OpenedAt: now, Expires: now.Add(SlotLife),
		SecretHash: hash(secret)}
	return s, Code{Fleet: fleet, URL: url, Pin: pin, Anchor: anchor, Slot: s.ID, Secret: secret}, nil
}

// Presentation is what the edge sends, over TLS pinned to the fleet: its public key, the code's single-use secret
// (the fleet keeps only its hash, so the secret proves the code), and its own signature over the fleet, the slot
// and the secret's commitment (proof of possession of the key, point 24).
type Presentation struct {
	Slot   string `json:"slot"`
	Key    string `json:"key"`    // ed25519 public key, hex
	Secret string `json:"secret"` // the code's secret, used once
	Sig    string `json:"sig"`    // hex ed25519 signature over presentMessage
}

func presentMessage(fleet, slot, secretHash string) []byte {
	return []byte(presentContext + "\n" + fleet + "\n" + slot + "\n" + secretHash)
}

// Present builds the edge's presentation from its code and key (what the installer does).
func Present(c Code, priv ed25519.PrivateKey) Presentation {
	key := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	return Presentation{Slot: c.Slot, Key: key, Secret: c.Secret,
		Sig: hex.EncodeToString(ed25519.Sign(priv, presentMessage(c.Fleet, c.Slot, hash(c.Secret))))}
}

// ErrTaken is a second presentation for a used slot: shown and alarmed, never a quiet replacement (point 15).
var ErrTaken = errors.New("slot already taken")

// Accept checks a presentation against its slot: the code's secret (by its hash), and the key's signature over the
// fleet, the slot and the commitment. Returns the slot with the key recorded.
func Accept(fleet string, s Slot, p Presentation, now time.Time) (Slot, error) {
	refuse := func(why string) (Slot, error) {
		s.Refused = append(s.Refused, now.UTC().Format(time.RFC3339)+" "+why)
		return s, errors.New(why)
	}
	switch {
	case s.Active || s.Key != "":
		s.Refused = append(s.Refused, now.UTC().Format(time.RFC3339)+" a second key for this slot")
		return s, ErrTaken
	case len(s.Refused) >= MaxRefused:
		return refuse("the slot is closed after refused presentations: open a new one")
	case !now.Before(s.Expires):
		return refuse("the slot has expired")
	case p.Slot != s.ID || !hmac.Equal([]byte(hash(p.Secret)), []byte(s.SecretHash)):
		return refuse("the code's secret does not match the slot")
	}
	key, err := hex.DecodeString(p.Key)
	sig, err2 := hex.DecodeString(p.Sig)
	if err != nil || err2 != nil || len(key) != ed25519.PublicKeySize {
		return refuse("the key is not an Ed25519 public key")
	}
	if !ed25519.Verify(key, presentMessage(fleet, s.ID, s.SecretHash), sig) {
		return refuse("the presentation does not prove the key (its signature)")
	}
	s.Key, s.Presented = p.Key, now
	return s, nil
}

// Fingerprint is how the edge's screen shows its key: base32 of sha256, in groups of four.
func Fingerprint(keyHex string) string {
	key, _ := hex.DecodeString(keyHex)
	sum := sha256.Sum256(key)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	var g []string
	for i := 0; i < len(enc); i += 4 {
		g = append(g, enc[i:min(i+4, len(enc))])
	}
	return strings.Join(g, " ")
}

func plain(s string) string { return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s)) }

// Item is one slot in an activation: what the approver saw and typed, and who read the screen.
type Item struct {
	Slot        string `json:"slot"`
	Fingerprint string `json:"fingerprint"` // the whole fingerprint the statement covers (point 24)
	Typed       string `json:"typed"`       // what the approver typed, as read from the edge's screen
	ReadBy      string `json:"read_by"`     // who read the screen (point 33)
	ReadHow     string `json:"read_how"`    // "on site", "phone", ...
}

// Activation is what one officer's passkey approves (points 15, 32).
type Activation struct {
	Fleet    string `json:"fleet"`
	Approver string `json:"approver"` // the officer's id
	Items    []Item `json:"items"`
}

// Hash is the activation's identity, the Body of the statement the passkey signs.
func (a Activation) Hash() string {
	b, _ := json.Marshal(a, json.Deterministic(true))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Activate checks an activation against the slots, the registry in force and the officer's signature, and returns
// the slots now active. Every item must name a presented slot with the fingerprint of its key and a typed check of
// at least 16 characters taken from it; a relay or site fleet only when the approver read the screen in person.
func Activate(rp registry.RP, reg registry.Registry, slots map[string]Slot, a Activation, st registry.Statement,
	sig registry.Signature, now time.Time) ([]Slot, error) {
	switch {
	case a.Fleet != reg.Fleet || st.Fleet != reg.Fleet:
		return nil, errors.New("an activation for another fleet")
	case st.Kind != "activate" || st.Body != a.Hash() || st.Registry != reg.Version:
		return nil, errors.New("the statement does not approve this activation under the registry in force")
	case sig.Officer != a.Approver:
		return nil, errors.New("the signature is not the approver's")
	}
	i := slices.IndexFunc(reg.Officers, func(o registry.Officer) bool { return o.ID == a.Approver })
	if i < 0 {
		return nil, fmt.Errorf("%s is not an officer", a.Approver)
	}
	if _, err := rp.Verify(sig, reg.Officers[i], st, now); err != nil {
		return nil, fmt.Errorf("the approver's passkey: %w", err)
	}
	return Check(slots, a, now)
}

// Check is Activate without the signature: whether every item names a presented slot with its key's whole
// fingerprint, a typed check taken from it and who read the screen. The page runs it before asking for the passkey.
func Check(slots map[string]Slot, a Activation, now time.Time) ([]Slot, error) {
	if len(a.Items) == 0 || len(a.Items) > MaxBatch {
		return nil, fmt.Errorf("an activation carries 1 to %d slots", MaxBatch)
	}
	var out []Slot
	seen := map[string]bool{}
	for _, it := range a.Items {
		s, ok := slots[it.Slot]
		switch {
		case !ok || seen[it.Slot]:
			return nil, fmt.Errorf("slot %s: unknown or listed twice", it.Slot)
		case s.Active || s.Key == "" || !now.Before(s.Expires):
			return nil, fmt.Errorf("slot %s (%s): not presented, expired, or already active", it.Slot, s.Name)
		case plain(it.Fingerprint) != plain(Fingerprint(s.Key)):
			return nil, fmt.Errorf("slot %s (%s): the statement's fingerprint is not the presented key's", it.Slot, s.Name)
		case len(plain(it.Typed)) < MinTyped || !strings.Contains(plain(it.Fingerprint), plain(it.Typed)):
			return nil, fmt.Errorf("slot %s (%s): type at least %d characters of the fingerprint from the edge's screen", it.Slot, s.Name, MinTyped)
		case it.ReadBy == "" || it.ReadHow == "":
			return nil, fmt.Errorf("slot %s (%s): record who read the screen and how", it.Slot, s.Name)
		case (s.Kind == Relay || s.Kind == Site) && (it.ReadBy != a.Approver || it.ReadHow != "on site"):
			return nil, fmt.Errorf("slot %s (%s): a %s is admitted only with the approver reading its screen on site", it.Slot, s.Name, s.Kind)
		}
		seen[it.Slot] = true
		s.Active = true
		out = append(out, s)
	}
	return out, nil
}
