package protocol

import (
	"encoding/json"
	"fmt"
)

// Rendezvous frame types (docs/whitepaper.md §9). The list is complete.
// There is no generic RPC frame and no frame that carries a command, a path,
// or a filename.
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
// JSON. The signer must verify the bytes the agent signed, not bytes the
// service re-serialized. A JSON round trip through float64 would also corrupt
// 64-bit values in the response.
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
func KnownFrame(t string) bool {
	switch t {
	case FrameHello, FrameRedeemRequest, FrameRedeemResponse, FramePing, FramePong:
		return true
	}
	return false
}
