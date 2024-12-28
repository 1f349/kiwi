package kiwi

type packetKind byte

const (
	packetKindHello       packetKind = 0x39
	packetKindHelloVerify packetKind = 0x2d
	packetKindHelloFinish packetKind = 0x92
	packetKindPing        packetKind = 0xb6
	packetKindPong        packetKind = 0x1a
	packetKindAck         packetKind = 0x7f
	packetKindUserData    packetKind = 0x55
)
