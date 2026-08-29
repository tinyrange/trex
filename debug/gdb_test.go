package debug

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

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
