package canonical_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/derekmeegan/grantd/go/internal/canonical"
)

// TestFieldContentCannotShiftAcrossBoundaries is the reason every field is
// length-prefixed and named. Without both, "ab"+"c" and "a"+"bc" would encode
// identically and an attacker could move bytes between adjacent fields while
// keeping a signature valid.
func TestFieldContentCannotShiftAcrossBoundaries(t *testing.T) {
	a := canonical.MustEncode("ctx", []canonical.Field{
		canonical.S("x", "ab"), canonical.S("y", "c"),
	})
	b := canonical.MustEncode("ctx", []canonical.Field{
		canonical.S("x", "a"), canonical.S("y", "bc"),
	})
	if bytes.Equal(a, b) {
		t.Fatal("adjacent string fields can be re-split without changing the encoding")
	}
}

func TestFieldNamesAreCovered(t *testing.T) {
	a := canonical.MustEncode("ctx", []canonical.Field{canonical.S("user", "root")})
	b := canonical.MustEncode("ctx", []canonical.Field{canonical.S("role", "root")})
	if bytes.Equal(a, b) {
		t.Fatal("field names are not covered by the encoding")
	}
}

func TestContextSeparatesOtherwiseIdenticalMessages(t *testing.T) {
	fields := []canonical.Field{canonical.U("version", 1), canonical.S("id", "g_x")}
	a := canonical.MustEncode("grantd/v1/redemption-agent-sig", fields)
	b := canonical.MustEncode("grantd/v1/redemption-proof", fields)
	if bytes.Equal(a, b) {
		t.Fatal("different contexts produced identical bytes")
	}
	// And the difference must not be something a length-extension could paper
	// over: the context is length-prefixed at the very front.
	if bytes.HasPrefix(b, a[:8]) && bytes.Equal(a[:4], b[:4]) && len(a) == len(b) {
		t.Log("contexts happen to be the same length; that is fine, bytes still differ")
	}
}

func TestFieldOrderIsSignificant(t *testing.T) {
	a := canonical.MustEncode("ctx", []canonical.Field{
		canonical.S("a", "1"), canonical.S("b", "2"),
	})
	b := canonical.MustEncode("ctx", []canonical.Field{
		canonical.S("b", "2"), canonical.S("a", "1"),
	})
	if bytes.Equal(a, b) {
		t.Fatal("field order does not affect the encoding")
	}
}

func TestRejectsInvalidUTF8(t *testing.T) {
	_, err := canonical.Encode("ctx", []canonical.Field{
		canonical.S("s", string([]byte{0xff, 0xfe})),
	})
	if err == nil {
		t.Fatal("invalid UTF-8 was accepted in a string field")
	}
}

func TestRejectsNulInString(t *testing.T) {
	_, err := canonical.Encode("ctx", []canonical.Field{canonical.S("s", "a\x00b")})
	if err == nil {
		t.Fatal("U+0000 was accepted in a string field")
	}
}

func TestRejectsU64AboveSignedRange(t *testing.T) {
	_, err := canonical.Encode("ctx", []canonical.Field{
		canonical.U("n", canonical.MaxU64+1),
	})
	if err == nil {
		t.Fatal("a u64 above 2^63-1 was accepted; signed-integer languages would disagree")
	}
}

func TestRejectsEmptyContextAndFieldName(t *testing.T) {
	if _, err := canonical.Encode("", []canonical.Field{canonical.S("a", "b")}); err == nil {
		t.Error("empty context was accepted")
	}
	if _, err := canonical.Encode("ctx", []canonical.Field{canonical.S("", "b")}); err == nil {
		t.Error("empty field name was accepted")
	}
}

func TestRejectsUnknownTag(t *testing.T) {
	_, err := canonical.Encode("ctx", []canonical.Field{{Name: "x", Tag: 0x7f}})
	if err == nil {
		t.Fatal("an unknown type tag was accepted")
	}
}

// TestUnicodeIsEncodedAsRawUTF8 guards against an implementation that escapes
// non-ASCII the way JSON would. Two implementations that disagree here produce
// different signatures for the same message.
func TestUnicodeIsEncodedAsRawUTF8(t *testing.T) {
	got := canonical.MustEncode("c", []canonical.Field{canonical.S("h", "höst")})
	if !bytes.Contains(got, []byte("h\xc3\xb6st")) {
		t.Fatalf("expected raw UTF-8 bytes in the encoding, got % x", got)
	}
	if bytes.Contains(got, []byte("\\u")) {
		t.Fatal("encoding contains a JSON-style escape sequence")
	}
}

func TestEncodingIsDeterministic(t *testing.T) {
	f := []canonical.Field{
		canonical.U("version", 1),
		canonical.S("host_id", strings.Repeat("h", 34)),
		canonical.B("nonce", []byte{1, 2, 3}),
		canonical.Bl("flag", true),
	}
	first := canonical.MustEncode("ctx", f)
	for i := 0; i < 100; i++ {
		if !bytes.Equal(first, canonical.MustEncode("ctx", f)) {
			t.Fatal("encoding is not deterministic")
		}
	}
}

func TestEmptyValuesStillOccupyTheirField(t *testing.T) {
	withEmpty := canonical.MustEncode("ctx", []canonical.Field{
		canonical.S("a", ""), canonical.S("b", "x"),
	})
	withoutField := canonical.MustEncode("ctx", []canonical.Field{
		canonical.S("b", "x"),
	})
	if bytes.Equal(withEmpty, withoutField) {
		t.Fatal("an empty field encodes the same as an absent field")
	}
}
