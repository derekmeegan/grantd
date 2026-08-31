package agent

import (
	"time"

	"github.com/derekmeegan/grantd/go/internal/protocol"
)

// BuildRedemption constructs the redemption envelope. It is separated from the
// HTTP call so that tests can hand the exact same bytes to a signer directly,
// with no service in the middle.
func BuildRedemption(ident *Identity, cap Capability, sshLine string, now time.Time) (protocol.RedemptionRequest, error) {
	nonce, err := protocol.NewNonce()
	if err != nil {
		return protocol.RedemptionRequest{}, err
	}
	p := protocol.RedemptionPayload{
		Version:        protocol.Version,
		HostID:         cap.HostID,
		GrantID:        cap.GrantID,
		AgentID:        ident.ID,
		AgentPublicKey: ident.PublicKey(),
		SSHPublicKey:   sshLine,
		Timestamp:      now.Unix(),
		Nonce:          nonce,
	}
	sigMsg, err := p.CanonicalSig()
	if err != nil {
		return protocol.RedemptionRequest{}, err
	}
	// The proof is the only thing that authorizes issuance, and it is computed
	// here from a secret that never touches the network.
	proof, err := p.Proof(cap.Secret)
	if err != nil {
		return protocol.RedemptionRequest{}, err
	}
	return protocol.RedemptionRequest{
		Payload:        p,
		AgentSignature: ident.Sign(sigMsg),
		Proof:          proof,
	}, nil
}
