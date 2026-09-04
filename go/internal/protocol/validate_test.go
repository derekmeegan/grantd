package protocol

import "testing"

// A real base32 host label: the alphabet is a-z and 2-7.
const testLabel = "abcdefghijklmnopqrstuvwxyz234567"

func TestHostDNSNameDerivesFromTheHostIDAlone(t *testing.T) {
	got, err := HostDNSName("h_"+testLabel, "hosts.grantd.dev")
	if err != nil {
		t.Fatalf("HostDNSName: %v", err)
	}
	if want := testLabel + ".hosts.grantd.dev"; got != want {
		t.Errorf("HostDNSName = %q, want %q", got, want)
	}
}

// The service derives the same name in cloudflare/src/dns.ts and writes only
// that record. A host id this client would accept but the service would not
// means an enrollment that silently never gets a name.
func TestHostDNSNameRejectsMalformedHostIDs(t *testing.T) {
	for _, bad := range []string{
		"a_" + testLabel,       // an agent id
		"h_short",              // too short
		"h_" + testLabel + "x", // too long
		"h_" + "0123456789abcdefghijklmnopqrstuv", // 0 and 1 are not base32
		testLabel, // no prefix
		"",
	} {
		if _, err := HostDNSName(bad, "hosts.grantd.dev"); err == nil {
			t.Errorf("HostDNSName(%q) should have failed", bad)
		}
	}
}

func TestValidateDNSSuffix(t *testing.T) {
	for _, ok := range []string{"hosts.grantd.dev", "example.com", "a.b.c.d"} {
		if err := ValidateDNSSuffix(ok); err != nil {
			t.Errorf("ValidateDNSSuffix(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"single",            // needs at least two labels
		"trailing.dot.",     // no trailing dot
		"-lead.example.com", // a label may not start with a hyphen
		"trail-.example.com",
		"a b.example.com",
		"under_score.example.com",
	} {
		if err := ValidateDNSSuffix(bad); err == nil {
			t.Errorf("ValidateDNSSuffix(%q) should have failed", bad)
		}
	}
}
