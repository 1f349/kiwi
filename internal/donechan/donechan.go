package donechan

import (
	"sync/atomic"
)

type DoneChan struct {
	C chan struct{}

	running atomic.Bool
}

func NewDoneChan() *DoneChan {
	return &DoneChan{
		C: make(chan struct{}),
	}
}

func (d *DoneChan) Close() {
	if !d.running.Swap(true) {
		close(d.C)
	}
}

func (d *DoneChan) Running() bool {
	return d.running.Load()
}
