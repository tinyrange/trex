package ethernet

import (
	"bytes"
	"testing"
)

func TestLearningOwnershipAndDisconnect(t *testing.T) {
	s := NewSwitch()
	a, b, c := s.Connect(), s.Connect(), s.Connect()
	frame := make([]byte, 60)
	copy(frame, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
	if err := a.Send(frame); err != nil {
		t.Fatal(err)
	}
	frame[14] = 99
	if got := b.Receive(); got == nil || got[14] != 0 {
		t.Fatal("queued frame aliases sender")
	}
	if c.Receive() == nil || a.Receive() != nil {
		t.Fatal("unknown unicast flooding")
	}
	copy(frame, []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
	if err := b.Send(frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Receive(), frame) || c.Receive() != nil {
		t.Fatal("learned unicast routing")
	}
	a.Close()
	if err := a.Send(frame); err != ErrClosed {
		t.Fatal(err)
	}
	b.Send(frame)
	if c.Receive() == nil {
		t.Fatal("disconnected address remained learned")
	}
	for i := 0; i < 300; i++ {
		b.Send(frame)
	}
	count := 0
	for c.Receive() != nil {
		count++
	}
	if count != 256 {
		t.Fatal("receive bound", count)
	}
}
