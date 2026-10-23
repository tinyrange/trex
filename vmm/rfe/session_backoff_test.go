package rfe

import (
	"context"
	"testing"
	"time"
)

func TestNativeSessionsBackOffRepeatedWatchedPageExits(t *testing.T) {
	code := []byte{0x40, 0x01, 0x07, 0x49, 0x75, 0xfa, 0xe6, 0xf2}
	actual, expected := jitCPU(t, 16, code), jitCPU(t, 16, code)
	for _, c := range []*cpu{actual, expected} {
		c.system.Segments[3].Base = 0x5000 // non-code data in an executed page
		c.core.R[3] = 0x900
		c.core.R[1] = 2048
	}
	referenceToPort(t, expected)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := actual.Run(ctx); err != nil {
		t.Fatal(err)
	}
	equalJITState(t, actual, expected)
	s := actual.jit.Stats()
	if s["native"] == 0 || s["native_sessions"] == 0 || s["native_sessions"] > 32 {
		t.Fatal("repeated guarded store paid a session for every short prefix", s)
	}
}
