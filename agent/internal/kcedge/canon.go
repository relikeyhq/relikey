// SPDX-License-Identifier: EUPL-1.2

// Package kcedge is the edge side of the KeyClerk edge interface (KeyClerk v0.19.0,
// docs/keyclerk-edge-interface.md): canonical bytes, sealed objects, the ceiling and the
// bundle verifier. It is a port of keyclerk/edge.py and must give the same verdicts
// (tests/conformance/edge.json).
package kcedge

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Value is a parsed JSON value as keyclerk.edge.canonical sees it: nil, bool, string,
// Number, []Value or Object. Floats do not exist in signed objects.
type Value any

// Number is an integer kept as its decimal text, so integers beyond int64 still
// re-encode exactly as Python prints them; typed decoding range-checks later.
type Number string

// Object is a JSON object; Encode writes its members sorted by name.
type Object map[string]Value

var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// Parse reads exactly one JSON value. It refuses duplicate names and invalid UTF-8
// (jsontext defaults), and numbers that are not integers or are "-0": Python's
// json.loads makes those floats, which keyclerk.edge.canonical refuses.
func Parse(b []byte) (Value, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(b))
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

func parseValue(dec *jsontext.Decoder) (Value, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	switch tok.Kind() {
	case 'n':
		return nil, nil
	case 't', 'f':
		return tok.Bool(), nil
	case '"':
		return tok.String(), nil
	case '0':
		s := tok.String()
		if !integer.MatchString(s) || s == "-0" {
			return nil, fmt.Errorf("number %q: signed objects carry whole numbers only", s)
		}
		return Number(s), nil
	case '[':
		arr := []Value{}
		for dec.PeekKind() != ']' {
			v, err := parseValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.ReadToken()
		return arr, err
	case '{':
		obj := Object{}
		for dec.PeekKind() != '}' {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			name := tok.String() // a Token is void after the next decoder call
			v, err := parseValue(dec)
			if err != nil {
				return nil, err
			}
			obj[name] = v
		}
		_, err := dec.ReadToken()
		return obj, err
	}
	return nil, fmt.Errorf("unexpected JSON token %v", tok.Kind())
}

// Encode writes v exactly as keyclerk.edge.canonical does: json.dumps with sort_keys,
// separators "," and ":", ensure_ascii False, UTF-8. Never use jsontext's
// Canonicalize: that is RFC 8785 (UTF-16 name order, integers through float64).
func Encode(v Value) []byte {
	var b bytes.Buffer
	encode(&b, v)
	return b.Bytes()
}

func encode(b *bytes.Buffer, v Value) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case Number:
		b.WriteString(string(x))
	case string:
		encodeString(b, x)
	case []Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			encode(b, e)
		}
		b.WriteByte(']')
	case Object:
		// Go compares strings bytewise; UTF-8 byte order is code point order, which is
		// Python's str order (lone surrogates cannot occur: Parse refuses them).
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		slices.Sort(names)
		b.WriteByte('{')
		for i, k := range names {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			encode(b, x[k])
		}
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("kcedge: %T is not part of a signed object", v))
	}
}

// encodeString follows Python's json encoder with ensure_ascii False: only the quote,
// the backslash and characters below 0x20 are escaped, the short forms where Python
// has them, otherwise \u00xx in lower case. Everything else is written as UTF-8.
func encodeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// CheckCanonical refuses bytes that keyclerk.edge.canonical would not have written:
// whitespace, unsorted or duplicate names, other escapes, non-integers, a BOM.
func CheckCanonical(b []byte) (Value, error) {
	v, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("not canonical JSON: %w", err)
	}
	if !bytes.Equal(Encode(v), b) {
		return nil, errors.New("the signed bytes are not canonical")
	}
	return v, nil
}

// errorList joins reasons the way the reference reports them.
func errorList(reasons []string) string { return strings.Join(reasons, "; ") }
