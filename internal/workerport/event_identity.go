package workerport

import (
	"crypto/rand"
	"encoding/hex"
)

func id() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
