package kiwi

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncode(t *testing.T) {
	b := encode(packetKindUserData, 1, []byte{0x54, 0xe5})
	fmt.Printf("%x\n", b)
}

func TestDecode(t *testing.T) {
	kind, data, err := decode([]byte{0x55, 0x00, 0x02, 0x54, 0xe5, 0x67, 0x20, 0x77, 0x23})
	assert.NoError(t, err)
	fmt.Printf("%x %x\n", kind, data)
}
