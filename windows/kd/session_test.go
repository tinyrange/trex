package kd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	channelpkg "github.com/tinyrange/trex/channel"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

func newTestThread(t *testing.T) *starlark.Thread {
	t.Helper()
	thread := &starlark.Thread{Name: "kd test"}
	resources := lifecycle.Install(thread)
	t.Cleanup(func() { _ = resources.Close() })
	return thread
}

func TestKDSessionStateContextAndPacketIDs(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	thread := newTestThread(t)
	value, err := Builtin(thread, nil, starlark.Tuple{channelstar.New("kd-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kd := value.(*kdSessionValue)
	defer kd.Close()

	targetErr := make(chan error, 1)
	go func() {
		state := make([]byte, kdStateChangeSize)
		binary.LittleEndian.PutUint32(state[0:4], kdStateException)
		binary.LittleEndian.PutUint16(state[4:6], 0)
		binary.LittleEndian.PutUint16(state[6:8], 1)
		binary.LittleEndian.PutUint64(state[24:32], 0x80401000)
		binary.LittleEndian.PutUint32(state[32:36], 0x80000003)
		binary.LittleEndian.PutUint64(state[48:56], 0xffffffff80402000)
		if err := writeKDTestData(target, kdPacketStateChange64, 0x80800000, state, false); err != nil {
			targetErr <- err
			return
		}
		wire := newKDWire(target, kdDefaultPacketLimit)
		ack, err := wire.readPacket()
		if err != nil {
			targetErr <- err
			return
		}
		if ack.Leader != kdControlPacketLeader || ack.Type != kdPacketAcknowledge {
			targetErr <- io.ErrUnexpectedEOF
			return
		}
		request, err := wire.readPacket()
		if err != nil {
			targetErr <- err
			return
		}
		if request.Type != kdPacketStateManipulate || kdU32(request.Payload, 0) != kdAPIGetContext {
			targetErr <- io.ErrUnexpectedEOF
			return
		}
		if err := writeKDTestControl(target, kdPacketAcknowledge, request.ID); err != nil {
			targetErr <- err
			return
		}
		response := make([]byte, kdManipulateSize+204)
		binary.LittleEndian.PutUint32(response[0:4], kdAPIGetContext)
		binary.LittleEndian.PutUint16(response[6:8], 1)
		contextData := response[kdManipulateSize:]
		binary.LittleEndian.PutUint32(contextData[176:180], 0x11223344)
		binary.LittleEndian.PutUint32(contextData[180:184], 0x1000)
		binary.LittleEndian.PutUint32(contextData[184:188], 0x80401000)
		binary.LittleEndian.PutUint32(contextData[196:200], 0x2000)
		if err := writeKDTestData(target, kdPacketStateManipulate, 0x80800001, response, false); err != nil {
			targetErr <- err
			return
		}
		responseAck, err := wire.readPacket()
		if err != nil {
			targetErr <- err
			return
		}
		if responseAck.Type != kdPacketAcknowledge {
			targetErr <- fmt.Errorf("set context response packet type=%#x id=%#x", responseAck.Type, responseAck.ID)
			return
		}
		request, err = wire.readPacket()
		if err != nil {
			targetErr <- err
			return
		}
		if request.Type != kdPacketStateManipulate || kdU32(request.Payload, 0) != kdAPISetContext {
			targetErr <- fmt.Errorf("set context request type=%#x api=%#x size=%d", request.Type, kdU32(request.Payload, 0), len(request.Payload))
			return
		}
		if err := writeKDTestControl(target, kdPacketAcknowledge, request.ID); err != nil {
			targetErr <- err
			return
		}
		contextData = request.Payload[kdManipulateSize:]
		if len(contextData) != 204 || kdU32(contextData, 176) != 0x11223344 || kdU32(contextData, 184) != 0x80401001 {
			targetErr <- fmt.Errorf("unexpected set context payload size=%d eax=%#x eip=%#x", len(contextData), kdU32(contextData, 176), kdU32(contextData, 184))
			return
		}
		response = make([]byte, kdManipulateSize)
		binary.LittleEndian.PutUint32(response[0:4], kdAPISetContext)
		binary.LittleEndian.PutUint16(response[6:8], 1)
		if err := writeKDTestData(target, kdPacketStateManipulate, 0x80800000, response, false); err != nil {
			targetErr <- err
			return
		}
		responseAck, err = wire.readPacket()
		if err != nil {
			targetErr <- err
			return
		}
		if responseAck.Type != kdPacketAcknowledge {
			targetErr <- fmt.Errorf("set context response packet type=%#x id=%#x", responseAck.Type, responseAck.ID)
			return
		}
		targetErr <- nil
	}()

	eventMethod, _ := kd.Attr("next_event")
	event, err := starlark.Call(thread, eventMethod.(starlark.Callable), nil, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(2)}})
	if err != nil {
		t.Fatal(err)
	}
	kind, _ := event.(starlark.HasAttrs).Attr("kind")
	if kind != starlark.String("exception") {
		t.Fatalf("event kind = %v", kind)
	}
	address, _ := event.(starlark.HasAttrs).Attr("address")
	if address.String() != "18446744071566270464" {
		t.Fatalf("exception address = %s", address)
	}
	contextMethod, _ := kd.Attr("context")
	contextValue, err := starlark.Call(thread, contextMethod.(starlark.Callable), nil, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(2)}})
	if err != nil {
		t.Fatal(err)
	}
	eax, _ := contextValue.(starlark.HasAttrs).Attr("eax")
	if eax.String() != "287454020" {
		t.Fatalf("eax = %s", eax)
	}
	raw, _ := contextValue.(starlark.HasAttrs).Attr("raw")
	setContextMethod, _ := kd.Attr("set_context")
	if _, err := starlark.Call(thread, setContextMethod.(starlark.Callable), starlark.Tuple{raw}, []starlark.Tuple{
		{starlark.String("eip"), starlark.MakeUint64(0x80401001)},
		{starlark.String("timeout"), starlark.Float(2)},
	}); err != nil {
		select {
		case target := <-targetErr:
			t.Fatalf("set context: %v (target: %v)", err, target)
		default:
			t.Fatal(err)
		}
	}
	select {
	case err := <-targetErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("target transcript did not finish")
	}
}

func TestKDLoadSymbolsPathFollowsTargetContext(t *testing.T) {
	const path = `\WINNT\System32\ntoskrnl.exe` + "\x00"
	payload := make([]byte, kdStateChangeSize+704+len(path))
	binary.LittleEndian.PutUint32(payload[0:4], kdStateLoadSymbols)
	binary.LittleEndian.PutUint32(payload[32:36], uint32(len(path)))
	binary.LittleEndian.PutUint64(payload[40:48], 0xffffffff80400000)
	binary.LittleEndian.PutUint32(payload[60:64], 0x190900)
	copy(payload[len(payload)-len(path):], path)

	session := &kdSessionValue{}
	event, err := session.stateChangeEvent(kdPacket{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	record := event.value.(*starvalue.Record)
	pathValue, err := record.Attr("path")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := starlark.AsString(pathValue); got != strings.TrimSuffix(path, "\x00") {
		t.Fatalf("path = %q", got)
	}
}

func TestKD32LoadSymbolsAndContinueLayout(t *testing.T) {
	const imagePath = `\WINNT\System32\ntoskrnl.exe` + "\x00"
	payload := make([]byte, 348+len(imagePath))
	binary.LittleEndian.PutUint32(payload[0:4], kdStateLoadSymbols)
	binary.LittleEndian.PutUint16(payload[4:6], 5)
	binary.LittleEndian.PutUint16(payload[6:8], 0)
	binary.LittleEndian.PutUint32(payload[16:20], 0x80131bca)
	binary.LittleEndian.PutUint32(payload[20:24], uint32(len(imagePath)))
	binary.LittleEndian.PutUint32(payload[24:28], 0x80100000)
	binary.LittleEndian.PutUint32(payload[36:40], 0x000d3fc0)
	copy(payload[len(payload)-len(imagePath):], imagePath)

	session := &kdSessionValue{}
	event, err := session.stateChange32Event(kdPacket{ID: kdInitialPacketID, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if event.kind != "load_symbols" {
		t.Fatalf("kind = %q", event.kind)
	}
	record := event.value.(*starvalue.Record)
	pathValue, _ := record.Attr("path")
	if got, _ := starlark.AsString(pathValue); got != strings.TrimSuffix(imagePath, "\x00") {
		t.Fatalf("path = %q", got)
	}
	baseValue, _ := record.Attr("base")
	if baseValue.String() != "2148532224" {
		t.Fatalf("base = %s", baseValue)
	}
	unionOffset, size := session.manipulateLayout()
	if unionOffset != 12 || size != kdManipulate32Size {
		t.Fatalf("manipulate layout = %d/%d", unionOffset, size)
	}
}

func TestKD32ExceptionExposesExceptionAddress(t *testing.T) {
	payload := make([]byte, 104)
	binary.LittleEndian.PutUint32(payload[0:4], kdStateException)
	binary.LittleEndian.PutUint32(payload[16:20], 0x80101000)
	binary.LittleEndian.PutUint32(payload[20:24], 0x80000003)
	binary.LittleEndian.PutUint32(payload[32:36], 0x80102000)

	session := &kdSessionValue{}
	event, err := session.stateChange32Event(kdPacket{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	record := event.value.(*starvalue.Record)
	address, _ := record.Attr("address")
	if address.String() != "2148540416" {
		t.Fatalf("exception address = %s", address)
	}
}

func TestKDContinueDoesNotEraseANewerStop(t *testing.T) {
	session := &kdSessionValue{stopped: true, stopGeneration: 4}
	generation := session.stopGeneration

	if _, err := session.stateChange32Event(kdPacket{Payload: make([]byte, 104)}); err != nil {
		t.Fatal(err)
	}
	session.stateMu.Lock()
	if session.stopGeneration == generation {
		t.Fatal("state change did not advance the stop generation")
	}
	session.stateMu.Unlock()
	session.markContinued(generation)
	session.stateMu.Lock()
	stopped := session.stopped
	session.stateMu.Unlock()
	if !stopped {
		t.Fatal("an older continue erased a newer stop")
	}
}

func TestKDVirtualAddressFollowsTargetArchitectureAndWireLayout(t *testing.T) {
	tests := []struct {
		name         string
		architecture string
		protocol64   bool
		address      uint64
		want         uint64
		wantError    bool
	}{
		{name: "i386 KD32 kernel", architecture: "i386", address: 0x80401000, want: 0x80401000},
		{name: "i386 KD64 kernel", architecture: "i386", protocol64: true, address: 0x80401000, want: 0xffffffff80401000},
		{name: "i386 KD64 user", architecture: "i386", protocol64: true, address: 0x7ffdf000, want: 0x7ffdf000},
		{name: "i386 sign extended", architecture: "i386", protocol64: true, address: 0xffffffff80401000, want: 0xffffffff80401000},
		{name: "i386 invalid", architecture: "i386", protocol64: true, address: 0x180401000, wantError: true},
		{name: "amd64 low canonical", architecture: "amd64", protocol64: true, address: 0x80401000, want: 0x80401000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := &kdSessionValue{architecture: test.architecture, protocolKnown: true, target64: test.protocol64}
			got, err := session.virtualAddress(test.address)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
			if err == nil && got != test.want {
				t.Fatalf("address = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestKDWireRejectsChecksumAndResynchronizes(t *testing.T) {
	client, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	wire := newKDWire(client, 1024)
	done := make(chan error, 1)
	go func() {
		_, _ = target.Write([]byte("garbage"))
		if err := writeKDTestData(target, kdPacketDebugIO, 1, []byte("payload"), true); err != nil {
			done <- err
			return
		}
		control := make([]byte, kdHeaderSize)
		_, err := io.ReadFull(target, control)
		done <- err
	}()
	packet, err := wire.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	if packet.Type != kdPacketDebugIO || string(packet.Payload) != "payload" {
		t.Fatalf("packet = %#v", packet)
	}
	valid, err := wire.validateAndAcknowledge(packet)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("bad checksum packet was accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKDWireAcknowledgesDuplicatesAndRejectsUnexpectedIDs(t *testing.T) {
	client, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	wire := newKDWire(client, 1024)
	done := make(chan error, 1)
	go func() {
		targetWire := newKDWire(target, 1024)
		for _, id := range []uint32{kdInitialPacketID, kdInitialPacketID, 0x12345678} {
			if err := writeKDTestData(target, kdPacketDebugIO, id, []byte("event"), false); err != nil {
				done <- err
				return
			}
			control, err := targetWire.readPacket()
			if err != nil {
				done <- err
				return
			}
			want := uint16(kdPacketAcknowledge)
			if id == 0x12345678 {
				want = kdPacketResend
			}
			if control.Type != want {
				done <- fmt.Errorf("control for %#x = %d, want %d", id, control.Type, want)
				return
			}
		}
		done <- nil
	}()
	for index, want := range []bool{true, false, false} {
		packet, err := wire.readPacket()
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := wire.validateAndAcknowledge(packet)
		if err != nil {
			t.Fatal(err)
		}
		if accepted != want {
			t.Fatalf("packet %d accepted = %v, want %v", index, accepted, want)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKDSessionSerializesPacketsUntilAcknowledged(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	thread := newTestThread(t)
	value, err := Builtin(thread, nil, starlark.Tuple{channelstar.New("kd-order-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kd := value.(*kdSessionValue)
	defer kd.Close()

	type sendResult struct {
		id  uint32
		ack <-chan error
		err error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	firstResult := make(chan sendResult, 1)
	secondResult := make(chan sendResult, 1)
	go func() {
		id, ack, err := kd.sendData(ctx, kdPacketDebugIO, []byte("first"))
		firstResult <- sendResult{id: id, ack: ack, err: err}
	}()
	targetWire := newKDWire(target, kdDefaultPacketLimit)
	first, err := targetWire.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	firstSend := <-firstResult
	if firstSend.err != nil || firstSend.id != kdInitialPacketID || string(first.Payload) != "first" {
		t.Fatalf("first send = %#v, packet = %#v", firstSend, first)
	}

	go func() {
		id, ack, err := kd.sendData(ctx, kdPacketDebugIO, []byte("second"))
		secondResult <- sendResult{id: id, ack: ack, err: err}
	}()
	if err := target.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := targetWire.readPacket(); err == nil {
		t.Fatal("second packet was written before the first packet was acknowledged")
	}
	if err := target.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := writeKDTestControl(target, kdPacketAcknowledge, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-firstSend.ack; err != nil {
		t.Fatal(err)
	}
	second, err := targetWire.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	secondSend := <-secondResult
	if secondSend.err != nil || secondSend.id != kdInitialPacketID^1 || string(second.Payload) != "second" {
		t.Fatalf("second send = %#v, packet = %#v", secondSend, second)
	}
	if err := writeKDTestControl(target, kdPacketAcknowledge, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-secondSend.ack; err != nil {
		t.Fatal(err)
	}
}

func TestKDSessionResendsAndResetInvalidatesInflightPacket(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	thread := newTestThread(t)
	value, err := Builtin(thread, nil, starlark.Tuple{channelstar.New("kd-reset-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kd := value.(*kdSessionValue)
	defer kd.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		id  uint32
		ack <-chan error
		err error
	}
	sent := make(chan result, 1)
	go func() {
		id, ack, err := kd.sendData(ctx, kdPacketDebugIO, []byte("retry"))
		sent <- result{id: id, ack: ack, err: err}
	}()
	wire := newKDWire(target, kdDefaultPacketLimit)
	first, err := wire.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	receipt := <-sent
	if receipt.err != nil {
		t.Fatal(receipt.err)
	}
	if err := writeKDTestControl(target, kdPacketResend, first.ID); err != nil {
		t.Fatal(err)
	}
	repeated, err := wire.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	if repeated.ID != first.ID || string(repeated.Payload) != string(first.Payload) {
		t.Fatalf("resent packet = %#v, first = %#v", repeated, first)
	}
	if err := writeKDTestControl(target, kdPacketReset, 0); err != nil {
		t.Fatal(err)
	}
	if err := <-receipt.ack; !errors.Is(err, errKDReset) {
		t.Fatalf("reset acknowledgement = %v", err)
	}

	nextSent := make(chan result, 1)
	go func() {
		id, ack, err := kd.sendData(ctx, kdPacketDebugIO, []byte("after-reset"))
		nextSent <- result{id: id, ack: ack, err: err}
	}()
	next, err := wire.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	nextReceipt := <-nextSent
	if next.ID != kdInitialPacketID || nextReceipt.id != kdInitialPacketID {
		t.Fatalf("packet ID after reset = %#x/%#x", next.ID, nextReceipt.id)
	}
	if err := writeKDTestControl(target, kdPacketAcknowledge, next.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-nextReceipt.ack; err != nil {
		t.Fatal(err)
	}
}

func writeKDTestData(writer io.Writer, kind uint16, id uint32, payload []byte, badChecksum bool) error {
	packet := make([]byte, kdHeaderSize+len(payload)+1)
	binary.LittleEndian.PutUint32(packet[0:4], kdPacketLeader)
	binary.LittleEndian.PutUint16(packet[4:6], kind)
	binary.LittleEndian.PutUint16(packet[6:8], uint16(len(payload)))
	binary.LittleEndian.PutUint32(packet[8:12], id)
	checksum := kdChecksum(payload)
	if badChecksum {
		checksum++
	}
	binary.LittleEndian.PutUint32(packet[12:16], checksum)
	copy(packet[kdHeaderSize:], payload)
	packet[len(packet)-1] = kdTrailingByte
	return channelpkg.WriteAll(writer, packet)
}

func writeKDTestControl(writer io.Writer, kind uint16, id uint32) error {
	packet := make([]byte, kdHeaderSize)
	binary.LittleEndian.PutUint32(packet[0:4], kdControlPacketLeader)
	binary.LittleEndian.PutUint16(packet[4:6], kind)
	binary.LittleEndian.PutUint32(packet[8:12], id)
	return channelpkg.WriteAll(writer, packet)
}
