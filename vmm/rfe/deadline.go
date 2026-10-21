package rfe

import (
	"sync/atomic"
	"time"
)

func (c *cpu) ContinueExecution() bool {
	return c.pending == nil && len(c.operations) == 0 && !c.closed
}

// The actual next PIT event, not a guest-instruction estimate, requests the
// native return. Context cancellation and external IRQ edges use the same flag.
func (c *cpu) armNativeDeadline() {
	p := &c.pit
	if p.start.IsZero() || p.reload == 0 || p.mode != 2 && p.mode != 3 && p.elapsed != 0 {
		if c.nativeTimer != nil {
			c.nativeTimer.Stop()
		}
		return
	}
	ticks := (p.elapsed + 1) * uint64(p.reload)
	deadline := p.start.Add(time.Duration(ticks/1193182)*time.Second + time.Duration((ticks%1193182)*uint64(time.Second)/1193182))
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	if c.nativeTimer == nil {
		c.nativeTimer = time.AfterFunc(delay, func() { atomic.StoreUint32(&c.nativeStop, 1) })
	} else {
		c.nativeTimer.Reset(delay)
	}
}
