package kiwi

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"slices"
)

const (
	// headerSize : magic byte + packet kind byte + uint32 sequence (4 bytes) + crc32 checksum (4 bytes) + uint16 length (2 bytes)
	headerSize int = 1 + 1 + 4 + 4 + 2

	// magicByte is an identifying mark for kiwi packets, it serves a quick filter for potentially valid packets
	magicByte = 0x6e
)

// encode constructs a kiwi packet from the inputs.
//
// The underlying array for the b slice is reused if there is enough space for a
// full packet.
func encode(kind packetKind, seq uint32, b []byte) []byte {
	length := len(b)
	fullSize := headerSize + length
	b = slices.Grow(b, fullSize)
	b = b[:fullSize]
	copy(b[headerSize:], b)

	// write header
	b[0] = magicByte
	b[1] = byte(kind)
	binary.BigEndian.PutUint32(b[2:6], seq)

	// leave space for the checksum
	binary.BigEndian.PutUint32(b[6:10], 0)

	binary.BigEndian.PutUint16(b[10:12], uint16(length))

	// calculate checksum with 00000000 in place of the checksum
	checksum := crc32.ChecksumIEEE(b)
	binary.BigEndian.PutUint32(b[6:10], checksum)
	return b
}

var (
	errInvalidPacketStructure = errors.New("invalid packet structure")
	errInvalidPacketLength    = errors.New("invalid packet length")
	errInvalidPacketChecksum  = errors.New("invalid packet checksum")
)

// decode parses a kiwi packet ready for handling kiwi protocol commands or
// forwarding child protocols.
//
// The underlying array for the b slice is reused by the data slice. The data
// slice should be copied, or a new allocation should be used for the input.
func decode(b []byte) (kind packetKind, seq uint32, data []byte, err error) {
	if len(b) < headerSize || b[0] != magicByte {
		return 0, 0, nil, errInvalidPacketStructure
	}
	kind = packetKind(b[1])
	seq = binary.BigEndian.Uint32(b[2:6])
	checksum := binary.BigEndian.Uint32(b[6:10])

	// zero out ready for checksum calculation
	binary.BigEndian.PutUint32(b[6:10], 0)

	if checksum != crc32.ChecksumIEEE(b) {
		return 0, 0, nil, errInvalidPacketChecksum
	}

	length := binary.BigEndian.Uint16(b[10:12])
	if int(length) != len(b)-headerSize {
		return 0, 0, nil, errInvalidPacketLength
	}

	data = b[headerSize:]
	return kind, seq, data, nil
}
