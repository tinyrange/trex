package debug

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func TestGDBResumeRejectsUnconsumedStop(t *testing.T) {
	session := &gdbSessionValue{stops: make(chan gdbStop, 1)}
	session.stops <- gdbStop{generation: 7, resumable: true}
	_, err := session.executionBuiltin(nil, "continue", "c", nil, nil)
	var typed *vmmapi.Error
	if !errors.As(err, &typed) || typed.Code != vmmapi.ErrorState {
		t.Fatalf("continue error = %v, want invalid-state VMM error", err)
	}
}

func TestGDBTerminalStopDoesNotReadRegisters(t *testing.T) {
	session := &gdbSessionValue{}
	value, err := session.finishStop(context.Background(), parseGDBStop([]byte("W00")))
	if err != nil {
		t.Fatal(err)
	}
	stop := value.(starlark.HasAttrs)
	resumable, _ := stop.Attr("resumable")
	reason, _ := stop.Attr("reason")
	if resumable != starlark.False || reason.String() != `"exited"` {
		t.Fatalf("terminal stop = reason %s resumable %s", reason, resumable)
	}
}

func newTestThread(t *testing.T) *starlark.Thread {
	t.Helper()
	thread := &starlark.Thread{Name: "gdb test"}
	resources := lifecycle.Install(thread)
	t.Cleanup(func() { _ = resources.Close() })
	return thread
}

func TestGDBWireRejectsBadChecksum(t *testing.T) {
	client, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	wire := newGDBWire(client)
	targetErr := make(chan error, 1)
	go func() {
		if err := writeAll(target, []byte("$broken#00")); err != nil {
			targetErr <- err
			return
		}
		ack := []byte{0}
		_, err := io.ReadFull(target, ack)
		if err == nil && ack[0] != '-' {
			err = fmt.Errorf("checksum rejection = %#x, want '-'", ack[0])
		}
		targetErr <- err
	}()
	if _, err := wire.read(); err == nil {
		t.Fatal("bad checksum packet was accepted")
	}
	if err := <-targetErr; err != nil {
		t.Fatal(err)
	}
}

func TestGDBWithRegisterRestoresAfterCallbackFailure(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	targetErr := make(chan error, 1)
	go func() {
		targetXML := `<target><architecture>i386</architecture><feature name="core"><reg name="eax" bitsize="32" regnum="0"/><reg name="eip" bitsize="32"/></feature></target>`
		transcript := []struct{ request, response string }{
			{"qSupported:multiprocess+;xmlRegisters=i386", "PacketSize=1000;QStartNoAckMode-"},
			{"qXfer:features:read:target.xml:0,f80", "l" + targetXML},
			{"p0", "78563412"},
			{"P0=efbeadde", "OK"},
			{"P0=78563412", "OK"},
		}
		for _, exchange := range transcript {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()

	thread := newTestThread(t)
	value, err := GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gdb := value.(*gdbSessionValue)
	defer gdb.Close()
	callback := starlark.NewBuiltin("callback", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return nil, fmt.Errorf("callback failed")
	})
	method, _ := gdb.Attr("with_register")
	_, err = starlark.Call(thread, method.(starlark.Callable), starlark.Tuple{
		starlark.String("eax"), starlark.MakeUint64(0xdeadbeef), callback,
	}, nil)
	if err == nil {
		t.Fatal("failing callback succeeded")
	}
	select {
	case err := <-targetErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GDB transcript did not complete")
	}
}

func TestGDBAddressSpaceReadsAndRestoresPageTable(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	targetErr := make(chan error, 1)
	go func() {
		targetXML := `<target><architecture>i386</architecture><feature name="core"><reg name="cr3" bitsize="32" regnum="0"/></feature></target>`
		transcript := []struct{ request, response string }{
			{"qSupported:multiprocess+;xmlRegisters=i386", "PacketSize=1000;QStartNoAckMode-"},
			{"qXfer:features:read:target.xml:0,f80", "l" + targetXML},
			{"p0", "00300000"},
			{"P0=00500000", "OK"},
			{"m1000,4", "01020304"},
			{"P0=00300000", "OK"},
		}
		for _, exchange := range transcript {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()

	thread := newTestThread(t)
	value, err := GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb-address-space-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gdb := value.(*gdbSessionValue)
	defer gdb.Close()
	addressSpaceMethod, _ := gdb.Attr("address_space")
	space, err := starlark.Call(thread, addressSpaceMethod.(starlark.Callable), starlark.Tuple{starlark.MakeInt(0x5000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	readMethod, _ := space.(starlark.HasAttrs).Attr("read_memory")
	data, err := starlark.Call(thread, readMethod.(starlark.Callable), starlark.Tuple{starlark.MakeInt(0x1000), starlark.MakeInt(4)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if data != starlark.Bytes("\x01\x02\x03\x04") {
		t.Fatalf("address-space data = %v", data)
	}
	if err := <-targetErr; err != nil {
		t.Fatal(err)
	}
}

func TestGDBAddressSpaceRejectsStaleGeneration(t *testing.T) {
	session := &gdbSessionValue{memoryLimit: defaultGDBMemoryLimit, registerMap: map[string]gdbRegister{"cr3": {Name: "cr3", Bits: 32}}}
	session.generation.Store(2)
	space := &gdbAddressSpaceValue{session: session, pageTable: 0x5000, kind: "user", generation: 1}
	_, err := space.readMemoryBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(0x1000), starlark.MakeInt(4)}, nil)
	if err == nil || !strings.Contains(err.Error(), "stale generation 1") {
		t.Fatalf("stale address-space error = %v", err)
	}
}

func TestGDBPointIsRestoredAfterDisabledCallbackFailure(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	targetErr := make(chan error, 1)
	go func() {
		targetXML := `<target><architecture>i386</architecture><feature name="core"><reg name="eax" bitsize="32" regnum="0"/></feature></target>`
		for _, exchange := range []struct{ request, response string }{
			{"qSupported:multiprocess+;xmlRegisters=i386", "PacketSize=1000;QStartNoAckMode-"},
			{"qXfer:features:read:target.xml:0,f80", "l" + targetXML},
			{"z1,1234,1", "OK"},
			{"Z1,1234,1", "OK"},
		} {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()
	thread := newTestThread(t)
	value, err := GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb-point-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gdb := value.(*gdbSessionValue)
	defer gdb.Close()
	point := &gdbPointValue{session: gdb, kind: 1, address: 0x1234, size: 1}
	method, _ := point.Attr("with_disabled")
	callback := starlark.NewBuiltin("fail", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return nil, fmt.Errorf("intentional callback failure")
	})
	if _, err := starlark.Call(thread, method.(starlark.Callable), starlark.Tuple{callback}, nil); err == nil {
		t.Fatal("failing callback succeeded")
	}
	if point.removed.Load() {
		t.Fatal("point remained removed after callback failure")
	}
	if err := <-targetErr; err != nil {
		t.Fatal(err)
	}
}

func TestGDBWithStateRestoresRegistersAndMemoryAfterCallbackFailure(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	targetErr := make(chan error, 1)
	go func() {
		targetXML := `<target><architecture>i386</architecture><feature name="core"><reg name="eax" bitsize="32" regnum="0"/></feature></target>`
		transcript := []struct{ request, response string }{
			{"qSupported:multiprocess+;xmlRegisters=i386", "PacketSize=1000;QStartNoAckMode-"},
			{"qXfer:features:read:target.xml:0,f80", "l" + targetXML},
			{"p0", "78563412"},
			{"m100,4", "01020304"},
			{"P0=efbeadde", "OK"},
			{"M100,4:aabbccdd", "OK"},
			{"M100,4:01020304", "OK"},
			{"P0=78563412", "OK"},
		}
		for _, exchange := range transcript {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()

	thread := newTestThread(t)
	value, err := GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb-state-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gdb := value.(*gdbSessionValue)
	defer gdb.Close()
	callback := starlark.NewBuiltin("mutate", func(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		writeRegister, _ := gdb.Attr("write_register")
		if _, err := starlark.Call(thread, writeRegister.(starlark.Callable), starlark.Tuple{starlark.String("eax"), starlark.MakeUint64(0xdeadbeef)}, nil); err != nil {
			return nil, err
		}
		writeMemory, _ := gdb.Attr("write_memory")
		if _, err := starlark.Call(thread, writeMemory.(starlark.Callable), starlark.Tuple{starlark.MakeInt(0x100), starlark.Bytes("\xaa\xbb\xcc\xdd")}, nil); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("callback failed")
	})
	method, _ := gdb.Attr("with_state")
	_, err = starlark.Call(thread, method.(starlark.Callable), starlark.Tuple{
		starlark.NewList([]starlark.Value{starlark.String("eax")}),
		starlark.NewList([]starlark.Value{starlark.Tuple{starlark.MakeInt(0x100), starlark.MakeInt(4)}}),
		callback,
	}, nil)
	if err == nil {
		t.Fatal("failing callback succeeded")
	}
	select {
	case err := <-targetErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GDB transcript did not complete")
	}
}

func TestGDBWaitSelectsStoppedThreadBeforeReadingRegisters(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	targetErr := make(chan error, 1)
	go func() {
		targetXML := `<target><architecture>i386</architecture><feature name="core"><reg name="eax" bitsize="32" regnum="0"/><reg name="eip" bitsize="32" regnum="1"/></feature></target>`
		transcript := []struct{ request, response string }{
			{"qSupported:multiprocess+;xmlRegisters=i386", "PacketSize=1000;QStartNoAckMode-"},
			{"qXfer:features:read:target.xml:0,f80", "l" + targetXML},
		}
		for _, exchange := range transcript {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		request, err := readGDBTestPacket(target)
		if err != nil {
			targetErr <- err
			return
		}
		if string(request) != "c" {
			targetErr <- fmt.Errorf("request = %q, want continue", request)
			return
		}
		if err := writeGDBTestPacket(target, []byte("T05thread:p01.02;")); err != nil {
			targetErr <- err
			return
		}
		for _, exchange := range []struct{ request, response string }{
			{"Hgp01.02", "OK"},
			{"g", "78563412efcdab90"},
		} {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()

	thread := newTestThread(t)
	value, err := GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb-wait-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gdb := value.(*gdbSessionValue)
	defer gdb.Close()
	resume, _ := gdb.Attr("continue")
	if _, err := starlark.Call(thread, resume.(starlark.Callable), nil, nil); err != nil {
		t.Fatal(err)
	}
	wait, _ := gdb.Attr("wait")
	stopped, err := starlark.Call(thread, wait.(starlark.Callable), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := stopped.(starlark.HasAttrs)
	for name, want := range map[string]string{
		"generation": "1", "reason": `"breakpoint"`, "resumable": "True", "thread": `"p01.02"`,
	} {
		got, err := stop.Attr(name)
		if err != nil || got.String() != want {
			t.Fatalf("stop.%s = %v, want %s (err=%v)", name, got, want, err)
		}
	}
	if gdb.generation.Load() != 1 {
		t.Fatalf("GDB generation = %d, want 1", gdb.generation.Load())
	}
	select {
	case err := <-targetErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GDB wait transcript did not complete")
	}
}

func TestGDBThreadEnumerationAndSelection(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	targetErr := make(chan error, 1)
	go func() {
		targetXML := `<target><architecture>i386</architecture><feature name="core"><reg name="eip" bitsize="32" regnum="0"/></feature></target>`
		transcript := []struct{ request, response string }{
			{"qSupported:multiprocess+;xmlRegisters=i386", "PacketSize=1000;QStartNoAckMode-"},
			{"qXfer:features:read:target.xml:0,f80", "l" + targetXML},
			{"qfThreadInfo", "mp01.01,p01.02"},
			{"qsThreadInfo", "l"},
			{"qC", "QCp01.02"},
			{"Hgp01.01", "OK"},
			{"Hcp01.01", "OK"},
		}
		for _, exchange := range transcript {
			request, err := readGDBTestPacket(target)
			if err != nil {
				targetErr <- err
				return
			}
			if string(request) != exchange.request {
				targetErr <- fmt.Errorf("request = %q, want %q", request, exchange.request)
				return
			}
			if err := writeGDBTestPacket(target, []byte(exchange.response)); err != nil {
				targetErr <- err
				return
			}
		}
		targetErr <- nil
	}()

	thread := newTestThread(t)
	value, err := GDBBuiltin(thread, nil, starlark.Tuple{channelstar.New("gdb-thread-test", client)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gdb := value.(*gdbSessionValue)
	defer gdb.Close()
	threads, _ := gdb.Attr("threads")
	listed, err := starlark.Call(thread, threads.(starlark.Callable), nil, nil)
	if err != nil || listed.String() != `["p01.01", "p01.02"]` {
		t.Fatalf("threads = %v, err=%v", listed, err)
	}
	currentThread, _ := gdb.Attr("current_thread")
	current, err := starlark.Call(thread, currentThread.(starlark.Callable), nil, nil)
	if err != nil || current != starlark.String("p01.02") {
		t.Fatalf("current thread = %v, err=%v", current, err)
	}
	selectThread, _ := gdb.Attr("select_thread")
	if _, err := starlark.Call(thread, selectThread.(starlark.Callable), starlark.Tuple{starlark.String("p01.01")}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-targetErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GDB thread transcript did not complete")
	}
}

func readGDBTestPacket(channel io.ReadWriter) ([]byte, error) {
	leader := []byte{0}
	if _, err := io.ReadFull(channel, leader); err != nil {
		return nil, err
	}
	if leader[0] != '$' {
		return nil, fmt.Errorf("GDB packet leader = %#x", leader[0])
	}
	var encoded []byte
	for {
		value := []byte{0}
		if _, err := io.ReadFull(channel, value); err != nil {
			return nil, err
		}
		if value[0] == '#' {
			break
		}
		encoded = append(encoded, value[0])
	}
	checksum := make([]byte, 2)
	if _, err := io.ReadFull(channel, checksum); err != nil {
		return nil, err
	}
	want, err := hex.DecodeString(string(checksum))
	if err != nil || len(want) != 1 {
		return nil, fmt.Errorf("invalid GDB checksum %q", checksum)
	}
	var got byte
	for _, value := range encoded {
		got += value
	}
	if got != want[0] {
		return nil, fmt.Errorf("GDB checksum = %#x, want %#x", got, want[0])
	}
	if err := writeAll(channel, []byte{'+'}); err != nil {
		return nil, err
	}
	var decoded []byte
	for index := 0; index < len(encoded); index++ {
		if encoded[index] == '}' {
			index++
			if index >= len(encoded) {
				return nil, fmt.Errorf("truncated GDB escape")
			}
			decoded = append(decoded, encoded[index]^0x20)
		} else {
			decoded = append(decoded, encoded[index])
		}
	}
	return decoded, nil
}

func writeGDBTestPacket(channel io.ReadWriter, payload []byte) error {
	var checksum byte
	for _, value := range payload {
		checksum += value
	}
	packet := append([]byte{'$'}, payload...)
	packet = append(packet, '#', "0123456789abcdef"[checksum>>4], "0123456789abcdef"[checksum&15])
	if err := writeAll(channel, packet); err != nil {
		return err
	}
	ack := []byte{0}
	if _, err := io.ReadFull(channel, ack); err != nil {
		return err
	}
	if ack[0] != '+' {
		return fmt.Errorf("GDB client acknowledgement = %#x", ack[0])
	}
	return nil
}
