package kiwi

import (
	mathrand "math/rand"
)

// Seq is a counter for packet id numbers.
//
// 0xf000_0000 - minute hint
// 0x0800_0000 - ack flag
// 0x07ff_ffff - sequence number
type Seq uint32

const (
	seqMinuteHintOffset = 32 - 4
	seqAckBitOffset     = 32 - 5

	seqMinuteHintMask Seq = 0xf000_000
	seqAckBitMask     Seq = 0x0800_0000

	seqMetaBitMask = seqMinuteHintMask | seqAckBitMask
	seqDataMask    = ^seqMetaBitMask
)

func RandSeq() Seq {
	return Seq(mathrand.Uint32() & 0x07ff_ffff)
}

func (s Seq) AddMeta(flag uint8, ack bool) Seq {
	if ack {
		s |= 1 << seqAckBitOffset
	}
	s |= Seq(flag) << seqMinuteHintOffset
	return s
}

// Increment safely adds one to the sequence number.
//
// Any meta bits are lost during this operation.
func (s Seq) Increment() Seq {
	return (s + 1) & seqDataMask
}

func (s Seq) MinuteHint() uint8 {
	return uint8(s >> seqMinuteHintOffset)
}

func (s Seq) RequestsAck() bool {
	return (s>>seqAckBitOffset)&1 == 1
}
