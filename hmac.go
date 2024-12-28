package kiwi

import (
	"crypto/hmac"
	"encoding/binary"
	"golang.org/x/crypto/blake2s"
	"hash"
	"time"
)

func hmacUtil(key, data []byte) []byte {
	mac := hmac.New(func() hash.Hash {
		b, _ := blake2s.New256(nil)
		return b
	}, key)
	mac.Write(data)
	return mac.Sum(nil)
}

const hmacTimeCycle = 20 * time.Second //time.Minute

func hmacGenerateSharedKey(key Key, t time.Time) (out [blake2s.Size]byte) {
	mac := hmac.New(func() hash.Hash {
		b, _ := blake2s.New256(nil)
		return b
	}, key[:])
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], uint64(t.UTC().Round(hmacTimeCycle).Unix()))
	mac.Write(tb[:])
	mac.Sum(out[:0])
	return out
}
