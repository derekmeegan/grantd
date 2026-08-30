package protocol

import (
	"encoding/json"
	"fmt"
)

// Rendezvous frame types (protocol/v1.md §10). This list is exhaustive and
// deliberately tiny. There is no generic RPC frame, and there will never be a
// frame that carries a command, a path, a filename, or a shell string: the
// coordination service must not be able to ask a customer machine to do
// anything except answer a redemption it can already verify locally.
const (
	FrameHello          = "hello"
	FrameRedeemRequest  = "redeem.request"
	FrameRedeemResponse = "redeem.response"
	FramePing           = "ping"
	FramePong           = "pong"
)

// Frame is the envelope for every rendezvous message.
//
// Payloads travel in BodyB64 as base64url of the exact bytes, never as nested
// JSON. That is not a serialization preference, it is the property the design
// depends on:
//
//   - The request body is what the signer verifies. If the coordination service
//     parsed and re-serialized it, the signer would be verifying bytes the
//     service produced rather than bytes the agent signed.
//   - The response body is the host's answer, and JSON round-tripping through a
//     language with only float64 numbers silently corrupts any 64-bit value in
//     it — a certificate serial, for instance.
//
// Opaque bytes make both problems structurally impossible instead of merely
// unlikely.
type Frame struct {
	Type            string `json:"t"`
	ID              string `json:"id,omitempty"`
	ProtocolVersion uint64 `json:"protocol_version,omitempty"`
	Status          int    `json:"status,omitempty"`
	BodyB64         string `json:"body_b64,omitempty"`
}

// SetBody stores raw payload bytes on the frame.
func (f *Frame) SetBody(raw []byte) { f.BodyB64 = B64.EncodeToString(raw) }

// Body returns the raw payload bytes, or an error if the encoding is malformed.
func (f *Frame) Body() ([]byte, error) {
	if f.BodyB64 == "" {
		return nil, nil
	}
	raw, err := B64.DecodeString(f.BodyB64)
	if err != nil {
		return nil, fmt.Errorf("protocol: frame body: %w", err)
	}
	return raw, nil
}

// BodyJSON is a convenience for callers that want the payload as a JSON value.
func (f *Frame) BodyJSON() (json.RawMessage, error) {
	raw, err := f.Body()
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// KnownFrame reports whether t is a frame type this protocol version defines.
// Unknown frames are dropped and counted, never interpreted.
func KnownFrame(t string) bool {
	switch t {
	case FrameHello, FrameRedeemRequest, FrameRedeemResponse, FramePing, FramePong:
		return true
	}
	return false
}
