package inspector

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

func cryptoRandRead(b []byte) (int, error) { return rand.Read(b) }
func base64URL(b []byte) string             { return base64.RawURLEncoding.EncodeToString(b) }
func hexEncode(b []byte) string             { return hex.EncodeToString(b) }
