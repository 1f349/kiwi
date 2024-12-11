package kiwi

import "net/netip"

type Handler func(b []byte, addr netip.AddrPort)
