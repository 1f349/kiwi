package kiwi

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncode(t *testing.T) {
	b := encode(packetKindData, 1, []byte{0x54, 0xe5})
	fmt.Printf("%x\n", b)
}

func TestDecode(t *testing.T) {
	kind, seq, data, err := decode([]byte{0x6e, 0x55, 0x00, 0x00, 0x00, 0x01, 0x98, 0x10, 0x69, 0x86, 0x00, 0x02, 0x54, 0xe5})
	assert.NoError(t, err)
	fmt.Printf("%x %d %x\n", kind, seq, data)
}
