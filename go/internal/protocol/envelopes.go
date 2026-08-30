package protocol

import (
	"encoding/json"
	"fmt"
)

// Wire size limits. Enforced by every party that parses an envelope so that a
// hostile peer cannot make anyone allocate without bound.
const (
	MaxRequestBytes   = 16 * 1024
	MaxSSHPubKeyBytes = 1024
	MaxAnswerBytes    = 256
	MaxPowNonceBytes  = 64
	MaxHostnameBytes  = 253
	MaxUsernameBytes  = 32
)

// HostRegisterRequest is the body of PUT /v1/hosts/:host_id.
type HostRegisterRequest struct {
	Registration HostRegistration `json:"registration"`
	Signature    []byte           `json:"-"`
}

type hostRegisterRequestJSON struct {
	Registration HostRegistration `json:"registration"`
	Signature    string           `json:"signature"`
}

func (r HostRegisterRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(hostRegisterRequestJSON{r.Registration, b64enc(r.Signature)})
}

func (r *HostRegisterRequest) UnmarshalJSON(data []byte) error {
	var j hostRegisterRequestJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	sig, err := b64dec("signature", j.Signature)
	if err != nil {
		return err
	}
	*r = HostRegisterRequest{Registration: j.Registration, Signature: sig}
	return nil
}

// GrantPublishRequest is the body of PUT /v1/hosts/:host_id/grants/:grant_id.
// It contains signed public metadata and no secret.
type GrantPublishRequest struct {
	Grant     Grant  `json:"-"`
	Signature []byte `json:"-"`
}

type grantPublishRequestJSON struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}

func (r GrantPublishRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(grantPublishRequestJSON{r.Grant, b64enc(r.Signature)})
}

func (r *GrantPublishRequest) UnmarshalJSON(data []byte) error {
	var j grantPublishRequestJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	sig, err := b64dec("signature", j.Signature)
	if err != nil {
		return err
	}
	*r = GrantPublishRequest{Grant: j.Grant, Signature: sig}
	return nil
}

// RedemptionRequest is the body of POST /v1/hosts/:h/grants/:g/redeem and is
// also the exact envelope forwarded, unchanged, all the way to the signer.
type RedemptionRequest struct {
	Payload        RedemptionPayload `json:"-"`
	AgentSignature []byte            `json:"-"`
	Proof          []byte            `json:"-"`
}

type redemptionRequestJSON struct {
	Payload        RedemptionPayload `json:"payload"`
	AgentSignature string            `json:"agent_signature"`
	Proof          string            `json:"proof"`
}

func (r RedemptionRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(redemptionRequestJSON{r.Payload, b64enc(r.AgentSignature), b64enc(r.Proof)})
}

func (r *RedemptionRequest) UnmarshalJSON(data []byte) error {
	var j redemptionRequestJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	sig, err := b64dec("agent_signature", j.AgentSignature)
	if err != nil {
		return err
	}
	proof, err := b64dec("proof", j.Proof)
	if err != nil {
		return err
	}
	*r = RedemptionRequest{Payload: j.Payload, AgentSignature: sig, Proof: proof}
	return nil
}

// RedemptionResponse is what a successful redeemer receives. Everything in it
// is public: it is enough to open an SSH connection and nothing more.
type RedemptionResponse struct {
	Hostname       string `json:"hostname"`
	Port           uint64 `json:"port"`
	User           string `json:"user"`
	Certificate    string `json:"certificate"`
	Serial         uint64 `json:"serial"`
	KeyID          string `json:"key_id"`
	ValidBefore    int64  `json:"valid_before"`
	ValidBeforeStr string `json:"valid_before_rfc3339,omitempty"`
}

// AgentRegisterRequest is the body of POST /v1/agents.
type AgentRegisterRequest struct {
	Registration AgentRegistration `json:"-"`
	Signature    []byte            `json:"-"`
}

type agentRegisterRequestJSON struct {
	Registration AgentRegistration `json:"registration"`
	Signature    string            `json:"signature"`
}

func (r AgentRegisterRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(agentRegisterRequestJSON{r.Registration, b64enc(r.Signature)})
}

func (r *AgentRegisterRequest) UnmarshalJSON(data []byte) error {
	var j agentRegisterRequestJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	sig, err := b64dec("signature", j.Signature)
	if err != nil {
		return err
	}
	*r = AgentRegisterRequest{Registration: j.Registration, Signature: sig}
	return nil
}

// PowSpec is the proof-of-work half of an Agent Captcha challenge.
type PowSpec struct {
	Prefix         string `json:"prefix"`
	DifficultyBits int    `json:"difficulty_bits"`
}

// Challenge is the response to POST /v1/agent-challenges.
type Challenge struct {
	ChallengeID string  `json:"challenge_id"`
	Version     uint64  `json:"version"`
	ExpiresAt   int64   `json:"expires_at"`
	Pow         PowSpec `json:"pow"`
	Question    string  `json:"question"`
}

// APIError is the uniform error envelope. Code is one of the constants in
// errors.go and is the thing clients should branch on; Message is for humans.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiErrorEnvelope struct {
	Error APIError `json:"error"`
}

func (e APIError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// MarshalErrorBody renders the standard error envelope.
func MarshalErrorBody(code, msg string) []byte {
	b, _ := json.Marshal(apiErrorEnvelope{APIError{Code: code, Message: msg}})
	return b
}

// ParseErrorBody extracts an APIError from a response body, if it is one.
func ParseErrorBody(body []byte) (APIError, bool) {
	var env apiErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Error.Code == "" {
		return APIError{}, false
	}
	return env.Error, true
}
