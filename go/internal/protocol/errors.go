package protocol

import "net/http"

// Error codes (docs/whitepaper.md §9). Clients branch on these strings; they are
// part of the frozen protocol and must not be renamed.
const (
	ErrCodeBadRequest         = "BAD_REQUEST"
	ErrCodeUnsupportedVersion = "UNSUPPORTED_VERSION"
	ErrCodeIDMismatch         = "ID_MISMATCH"
	ErrCodeBadSignature       = "BAD_SIGNATURE"
	ErrCodeStaleTimestamp     = "STALE_TIMESTAMP"
	ErrCodeReplayedNonce      = "REPLAYED_NONCE"
	ErrCodeHostNotFound       = "HOST_NOT_FOUND"
	ErrCodeGrantNotFound      = "GRANT_NOT_FOUND"
	ErrCodeAgentNotFound      = "AGENT_NOT_FOUND"
	ErrCodeChallengeNotFound  = "CHALLENGE_NOT_FOUND"
	ErrCodeChallengeConsumed  = "CHALLENGE_CONSUMED"
	ErrCodeBadAnswer          = "BAD_ANSWER"
	ErrCodeHostOffline        = "HOST_OFFLINE"
	ErrCodeHostTimeout        = "HOST_TIMEOUT"
	ErrCodeGrantExpired       = "GRANT_EXPIRED"
	ErrCodeGrantRevoked       = "GRANT_REVOKED"
	ErrCodeAlreadyRedeemed    = "GRANT_ALREADY_REDEEMED"
	ErrCodeBadProof           = "BAD_PROOF"
	ErrCodeRateLimited        = "RATE_LIMITED"
	ErrCodeTooManyGrants      = "TOO_MANY_GRANTS"
	ErrCodeInternal           = "INTERNAL"
)

// HTTPStatusFor maps an error code to its canonical HTTP status.
func HTTPStatusFor(code string) int {
	switch code {
	case ErrCodeBadRequest, ErrCodeUnsupportedVersion, ErrCodeIDMismatch:
		return http.StatusBadRequest
	case ErrCodeBadSignature, ErrCodeStaleTimestamp, ErrCodeReplayedNonce,
		ErrCodeBadAnswer, ErrCodeBadProof:
		return http.StatusUnauthorized
	case ErrCodeHostNotFound, ErrCodeGrantNotFound, ErrCodeAgentNotFound,
		ErrCodeChallengeNotFound:
		return http.StatusNotFound
	case ErrCodeChallengeConsumed, ErrCodeAlreadyRedeemed:
		return http.StatusConflict
	case ErrCodeGrantExpired, ErrCodeGrantRevoked:
		return http.StatusGone
	case ErrCodeRateLimited, ErrCodeTooManyGrants:
		return http.StatusTooManyRequests
	case ErrCodeHostOffline:
		return http.StatusServiceUnavailable
	case ErrCodeHostTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}
