package kiwi

import (
	"encoding/binary"
	"slices"
)

// segmentHeaderSize : uint32 segment id (4 bytes) + uint16 page number (2 bytes) + uint16 page total (2 bytes)
const segmentHeaderSize int = 4 + 2 + 2

// encodeSegment constructs a kiwi segment packet from the inputs.
//
// The underlying array for the b slice is reused if there is enough space for a
// full packet.
func encodeSegment(segmentId uint32, page, total uint16, b []byte) []byte {
	length := len(b)
	fullSize := segmentHeaderSize + length
	b = slices.Grow(b, fullSize)
	b = b[:fullSize]
	copy(b[headerSize:], b)

	binary.BigEndian.PutUint32(b[0:4], segmentId)

	// write page numbers
	binary.BigEndian.PutUint16(b[4:6], page)
	binary.BigEndian.PutUint16(b[6:8], total)

	return b
}

// decodeSegment parses a kiwi segment packet ready for reassembly.
//
// The underlying array for the b slice is reused by the data slice. The data
// slice should be copied, or a new allocation should be used for the input.
func decodeSegment(b []byte) (segmentId uint32, page, total uint16, data []byte, err error) {
	if len(b) < segmentHeaderSize {
		return 0, 0, 0, nil, errInvalidPacketStructure
	}

	segmentId = binary.BigEndian.Uint32(b[0:4])
	page = binary.BigEndian.Uint16(b[4:6])
	total = binary.BigEndian.Uint16(b[6:8])

	data = b[headerSize:]
	return segmentId, page, total, data, nil
}
