package kiwi

import "testing"

func TestRandSeq(t *testing.T) {
	for i := 0; i < 100_000_000; i++ {
		if RandSeq() > 0x7ff_ffff {
			t.Fatal("RandSeq() > 0x7ff_ffff")
		}
	}
}
