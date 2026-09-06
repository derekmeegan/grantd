package warden

import (
	"errors"
	"strings"

	"github.com/derekmeegan/grantd/go/internal/protocol"
)

// ErrBadKeyID reports a certificate key id that grantd's CA did not write.
var ErrBadKeyID = errors.New("warden: key id is not a grantd key id")

// ParseKeyID splits a certificate key id of the form grantd:<grant>:<agent>
// into its grant and agent ids. The CA writes this label into every
// certificate it signs (see internal/sshcert), and sshd hands it to the
// admission command from the certificate it verified, so it is the one
// piece of the certificate the warden reads.
func ParseKeyID(keyID string) (grantID, agentID string, err error) {
	parts := strings.Split(keyID, ":")
	if len(parts) != 3 || parts[0] != "grantd" {
		return "", "", ErrBadKeyID
	}
	if !protocol.ValidGrantID(parts[1]) || !protocol.ValidAgentID(parts[2]) {
		return "", "", ErrBadKeyID
	}
	return parts[1], parts[2], nil
}
