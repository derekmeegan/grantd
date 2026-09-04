// Package canonical implements Canonical Binary Encoding (CBE) as specified
// in docs/whitepaper.md §5.1. A message is a flat, ordered list of typed,
// named fields under a domain separation string. There is no key ordering,
// escaping, or number formatting to get wrong.
package canonical

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// Value type tags. These are protocol constants and must never be renumbered.
const (
	TagString byte = 0x01
	TagU64    byte = 0x02
	TagBytes  byte = 0x03
	TagBool   byte = 0x04
)

// MaxU64 is the largest U64 the protocol permits. The limit keeps languages
// with signed 64-bit integers in agreement with unsigned ones.
const MaxU64 uint64 = math.MaxInt64

var (
	ErrInvalidUTF8 = errors.New("canonical: string field is not valid UTF-8")
	ErrNulInString = errors.New("canonical: string field contains U+0000")
	ErrU64Range    = errors.New("canonical: u64 field exceeds 2^63-1")
	ErrEmptyName   = errors.New("canonical: field name is empty")
	ErrEmptyCtx    = errors.New("canonical: context is empty")
)

// Field is one named, typed element of a message. Fields are encoded in slice
// order, which must match docs/whitepaper.md.
type Field struct {
	Name string
	Tag  byte
	// Tag selects which one of these carries the value.
	Str   string
	U64   uint64
	Bytes []byte
	Bool  bool
}

// S builds a STRING field.
func S(name, v string) Field { return Field{Name: name, Tag: TagString, Str: v} }

// U builds a U64 field.
func U(name string, v uint64) Field { return Field{Name: name, Tag: TagU64, U64: v} }

// B builds a BYTES field.
func B(name string, v []byte) Field { return Field{Name: name, Tag: TagBytes, Bytes: v} }

// Bl builds a BOOL field.
func Bl(name string, v bool) Field { return Field{Name: name, Tag: TagBool, Bool: v} }

// Encode returns the canonical bytes for a message.
//
//	CBE(context, fields) =
//	     LP(utf8(context))
//	  || u32be(len(fields))
//	  || for each field: LP(utf8(name)) || tag || LP(value)
func Encode(context string, fields []Field) ([]byte, error) {
	if context == "" {
		return nil, ErrEmptyCtx
	}
	if !utf8.ValidString(context) {
		return nil, ErrInvalidUTF8
	}
	var buf bytes.Buffer
	writeLP(&buf, []byte(context))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(fields)))
	buf.Write(n[:])

	for i, f := range fields {
		if f.Name == "" {
			return nil, fmt.Errorf("field %d: %w", i, ErrEmptyName)
		}
		if !utf8.ValidString(f.Name) {
			return nil, fmt.Errorf("field %d name: %w", i, ErrInvalidUTF8)
		}
		writeLP(&buf, []byte(f.Name))
		buf.WriteByte(f.Tag)

		switch f.Tag {
		case TagString:
			if !utf8.ValidString(f.Str) {
				return nil, fmt.Errorf("field %q: %w", f.Name, ErrInvalidUTF8)
			}
			if strings.ContainsRune(f.Str, 0) {
				return nil, fmt.Errorf("field %q: %w", f.Name, ErrNulInString)
			}
			writeLP(&buf, []byte(f.Str))
		case TagU64:
			if f.U64 > MaxU64 {
				return nil, fmt.Errorf("field %q: %w", f.Name, ErrU64Range)
			}
			var v [8]byte
			binary.BigEndian.PutUint64(v[:], f.U64)
			writeLP(&buf, v[:])
		case TagBytes:
			writeLP(&buf, f.Bytes)
		case TagBool:
			b := byte(0x00)
			if f.Bool {
				b = 0x01
			}
			writeLP(&buf, []byte{b})
		default:
			return nil, fmt.Errorf("canonical: field %q has unknown tag 0x%02x", f.Name, f.Tag)
		}
	}
	return buf.Bytes(), nil
}

// MustEncode panics on error. Tests and vector generation only.
func MustEncode(context string, fields []Field) []byte {
	b, err := Encode(context, fields)
	if err != nil {
		panic(err)
	}
	return b
}

func writeLP(buf *bytes.Buffer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}
