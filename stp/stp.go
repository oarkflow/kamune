// Package stp stands for: signed transfer protocol, or secure telecommunication
// passthrough; or (to anyone involved in internet censorship) suck this, punks.
package stp

type SignedTransport struct {
	Audience  string `json:"aud,omitempty"`
	Message   []byte `json:"msg"`
	Signature []byte `json:"sig"`
}
