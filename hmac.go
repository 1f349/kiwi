package kiwi

import (
	"crypto/hmac"
	"encoding/binary"
	"golang.org/x/crypto/blake2s"
	"hash"
	"time"
)

var hmacTimeCycle = time.Minute

func hmacGenerateSharedKey(key Key, t time.Time, pubKey Key) (out [blake2s.Size]byte) {
	mac := hmac.New(func() hash.Hash {
		b, _ := blake2s.New256(nil)
		return b
	}, key[:])
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], uint64(t.UTC().Round(hmacTimeCycle).Unix()))
	mac.Write(tb[:])
	mac.Write(pubKey[:])
	mac.Sum(out[:0])
	return out
}
