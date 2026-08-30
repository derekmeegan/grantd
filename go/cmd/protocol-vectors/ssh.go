package main

import (
	"crypto/ed25519"

	"github.com/derekmeegan/grantd/go/internal/idkey"
)

func sshPublicLine(pub ed25519.PublicKey) (string, error) { return idkey.PublicSSHLine(pub) }
