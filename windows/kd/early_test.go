package kd

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/tinyrange/trex/channel"
)

func TestEarlyKDSplitFrameAndMIPSContext(t *testing.T) {
	host, target, err := channel.NewMemoryPair(4096)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewEarlySession(host)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.BreakIn(); err != nil {
		t.Fatal(err)
	}
	var breakin [1]byte
	if _, err := io.ReadFull(target, breakin[:]); err != nil || breakin[0] != 0x62 {
		t.Fatalf("break-in %x, %v", breakin, err)
	}
	state := make([]byte, earlyWaitStateSize)
	le := binary.LittleEndian
	le.PutUint32(state, kdStateException)
	le.PutUint32(state[16:], 0x800320b0)
	le.PutUint32(state[20:], 0x80000003)
	le.PutUint32(state[32:], 0x800320b0)
	le.PutUint32(state[56:], 1)
	frame := earlyFrame(kdPacketStateChange32, state)
	if err = channel.WriteAll(target, append([]byte("console"), frame[:3]...)); err != nil {
		t.Fatal(err)
	}
	if got, err := session.Poll(); err != nil || got != nil {
		t.Fatalf("partial event %+v, %v", got, err)
	}
	if err = channel.WriteAll(target, frame[3:]); err != nil {
		t.Fatal(err)
	}
	ev, err := session.Poll()
	if err != nil || ev == nil || ev.PC != 0x800320b0 || !ev.FirstChance || !session.Stopped() {
		t.Fatalf("exception %+v, %v", ev, err)
	}
	if err := session.Request(kdAPIGetContext, 0, 0, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, earlyHeaderSize+earlyManipulateSize)
	if _, err := io.ReadFull(target, request); err != nil || string(request[:4]) != "0000" ||
		le.Uint16(request[4:]) != 24 || le.Uint16(request[6:]) != 2 || le.Uint32(request[8:]) != kdAPIGetContext {
		t.Fatalf("context request %x, %v", request, err)
	}
	payload := make([]byte, earlyManipulateSize+earlyContextSize)
	le.PutUint32(payload, kdAPIGetContext)
	le.PutUint32(payload[earlyManipulateSize+0x11c:], ev.PC)
	le.PutUint32(payload[earlyManipulateSize+0x10c:], 0x1234)
	if err = channel.WriteAll(target, earlyFrame(kdPacketStateManipulate, payload)); err != nil {
		t.Fatal(err)
	}
	ev, err = session.Poll()
	if err != nil || ev == nil || ev.Context == nil || ev.Context.PC != 0x800320b0 || ev.Context.GPR[31] != 0x1234 {
		t.Fatalf("context %+v, %v", ev, err)
	}
	if err = session.Request(kdAPIContinue, 0, kdContinueStatus, 0, 0, nil); err != nil || session.Stopped() {
		t.Fatalf("continue %v, stopped %v", err, session.Stopped())
	}
}

func TestEarlyKDRejectsTruncatedDebugIO(t *testing.T) {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint32(payload[8:], 1)
	if _, err := parseEarlyEvent(kdPacketDebugIO, payload); err == nil {
		t.Fatal("accepted inconsistent debug text length")
	}
}

func TestEarlyKDPromptReply(t *testing.T) {
	host, target, err := channel.NewMemoryPair(4096)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewEarlySession(host)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	payload := make([]byte, 16)
	le := binary.LittleEndian
	le.PutUint32(payload, kdAPIGetString)
	le.PutUint32(payload[4:], 1)
	le.PutUint32(payload[8:], 7)
	le.PutUint32(payload[12:], 5)
	if err := channel.WriteAll(target, earlyFrame(kdPacketDebugIO, append(payload, "NT SM> "...))); err != nil {
		t.Fatal(err)
	}
	event, err := session.Poll()
	if err != nil || event == nil || event.Kind != "prompt" || event.Limit != 5 || event.Text != "NT SM> " {
		t.Fatalf("prompt %+v, %v", event, err)
	}
	if err = session.ReplyPrompt([]byte("longer")); err == nil {
		t.Fatal("oversized response accepted")
	}
	if err = session.ReplyPrompt([]byte("sm\n")); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 27)
	if _, err = io.ReadFull(target, frame); err != nil || le.Uint16(frame[4:]) != 19 || le.Uint16(frame[6:]) != 3 ||
		le.Uint32(frame[8:]) != kdAPIGetString || le.Uint32(frame[12:]) != 1 || le.Uint32(frame[20:]) != 3 || string(frame[24:]) != "sm\n" {
		t.Fatalf("prompt response %x, %v", frame, err)
	}
	if err = session.ReplyPrompt(nil); err == nil {
		t.Fatal("duplicate prompt reply accepted")
	}
}
