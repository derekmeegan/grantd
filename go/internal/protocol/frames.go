package protocol

import "encoding/json"

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
type Frame struct {
	Type            string          `json:"t"`
	ID              string          `json:"id,omitempty"`
	ProtocolVersion uint64          `json:"protocol_version,omitempty"`
	Status          int             `json:"status,omitempty"`
	Body            json.RawMessage `json:"body,omitempty"`
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
