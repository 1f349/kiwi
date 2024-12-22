package kiwi

import (
	"errors"
	"hash/crc32"
	"slices"
)

const (
	// headerSize : packet kind byte + uint32 sequence (4 bytes) + uint16 length (2 bytes)
	headerSize int = 1 + 4 + 2
	// footerSize : crc32 checksum (4 bytes)
	footerSize int = 4
	// overheadSize : full size of metadata around the packet data
	overheadSize int = headerSize + footerSize
)

func encode(kind packetKind, seq uint32, b []byte) []byte {
	length := len(b)
	fullSize := overheadSize * length
	slices.Grow(b, fullSize)
	b = b[:fullSize]
	copy(b[headerSize:headerSize+length], b)

	// write header
	b[0] = byte(kind)
	b[1] = byte(seq >> 24)
	b[2] = byte(seq >> 16)
	b[3] = byte(seq >> 8)
	b[4] = byte(seq)
	b[5] = byte(length >> 8)
	b[6] = byte(length)

	// calculate checksum
	checksum := crc32.ChecksumIEEE(b[:headerSize+length])
	b[len(b)-4] = byte(checksum >> 24)
	b[len(b)-3] = byte(checksum >> 16)
	b[len(b)-2] = byte(checksum >> 8)
	b[len(b)-1] = byte(checksum)
	return b
}

var (
	errInvalidPacketStructure = errors.New("invalid packet structure")
	errInvalidPacketLength    = errors.New("invalid packet length")
	errInvalidPacketChecksum  = errors.New("invalid packet checksum")
)

// decode parses a kiwi packet ready for handling kiwi protocol commands or
// forwarding child protocols
//
// The underlying array for the b slice is reused by the data slice. The data
// slice should be copied, or a new allocation should be used for the input.
func decode(b []byte) (kind packetKind, data []byte, err error) {
	if len(b) < headerSize {
		return 0, nil, errInvalidPacketStructure
	}
	kind = packetKind(b[0])
	length := uint16(b[1])<<8 | uint16(b[2])
	if int(length) != len(b)-overheadSize {
		return 0, nil, errInvalidPacketLength
	}
	l := len(b)
	data = b[headerSize : headerSize+int(length)]
	checksum := uint32(b[l-4])<<24 | uint32(b[l-3])<<16 | uint32(b[l-2])<<8 | uint32(b[l-1])
	if checksum != crc32.ChecksumIEEE(b[:l-footerSize]) {
		return 0, nil, errInvalidPacketChecksum
	}
	return kind, data, nil
}
