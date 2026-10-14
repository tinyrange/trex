package cc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/channel"
)

// The Apple virtual USB protocol posts receive buffers to
// queue 0. Requests carry a six-byte length/endpoint/operation header; queue 1
// responses carry operation/endpoint followed by their optional payload.
const appleUSBPCIReceiveSize = 128 << 10

type appleUSBPCI struct {
	*virtioPCI
	host           channel.ByteChannel
	emit           func(string, any)
	input          []byte
	discardCurrent bool
}

func newAppleUSBPCI(configBase uint64, bar uint32, host channel.ByteChannel, memory func(uint64, uint64, bool) ([]byte, error), msi func(uint64, uint32) error, emit func(string, any)) *appleUSBPCI {
	d := &appleUSBPCI{host: host, emit: emit}
	d.virtioPCI = newVirtioPCI(virtioPCIOptions{
		ConfigBase: configBase, BAR: bar,
		VendorID: 0x106b, DeviceID: 0x1a01, SubsystemVendorID: 0x106b, SubsystemID: 0x1a01,
		Revision: 1, Class: 0x0c, Subclass: 3,
		QueueCount: 2, QueueRequest: d.request, Reset: d.resetInput,
	}, memory, msi)
	return d
}

func (d *appleUSBPCI) resetInput() {
	// The host byte stream survives a transport reset. Retain enough framing
	// state to discard the interrupted packet without mistaking its tail for
	// the next packet's header; none of that packet reaches the new queue.
	d.discardCurrent = len(d.input) != 0
}

func (d *appleUSBPCI) request(queue uint16, parts []virtioBuffer) (uint32, bool, error) {
	if d.host == nil {
		return 0, false, fmt.Errorf("Apple USB PCI: no host channel")
	}
	if queue > 1 {
		return 0, false, fmt.Errorf("Apple USB PCI: invalid queue %d", queue)
	}
	limit := appleUSBPCIReceiveSize
	if queue == 1 {
		limit = appleUSBPayloadLimit + 2
	}
	length := 0
	for _, part := range parts {
		if part.write != (queue == 0) || len(part.data) > limit-length {
			return 0, false, fmt.Errorf("Apple USB PCI: invalid queue %d descriptor", queue)
		}
		length += len(part.data)
	}
	if queue == 1 {
		return d.transmit(parts, length)
	}
	if length < 6 {
		return 0, false, fmt.Errorf("Apple USB PCI: receive buffer shorter than header")
	}
	// Reading the stream may consume a partial frame, but guest RAM and its
	// used ring remain unchanged until the complete frame has been received.
	for {
		want := 6
		if len(d.input) >= 6 {
			payload := binary.LittleEndian.Uint32(d.input)
			capacity := length
			if d.discardCurrent {
				capacity = appleUSBPCIReceiveSize
			}
			if payload > uint32(capacity-6) {
				return 0, false, fmt.Errorf("Apple USB PCI: host payload %d exceeds receive buffer", payload)
			}
			want += int(payload)
		}
		if len(d.input) == want {
			if d.discardCurrent {
				d.input = nil
				d.discardCurrent = false
				continue
			}
			at := 0
			for _, part := range parts {
				at += copy(part.data, d.input[at:])
			}
			if d.emit != nil {
				d.emit("apple.usb_receive", map[string]any{"endpoint": d.input[4], "operation": d.input[5], "length": want - 6})
			}
			d.input = nil
			return uint32(want), true, nil
		}
		var buffer [4096]byte
		n, err := d.host.Read(buffer[:min(len(buffer), want-len(d.input))])
		d.input = append(d.input, buffer[:n]...)
		if err != nil {
			if errors.Is(err, channel.ErrWouldBlock) {
				return 0, false, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				if len(d.input) != 0 {
					return 0, false, io.ErrUnexpectedEOF
				}
				return 0, false, nil
			}
			return 0, false, fmt.Errorf("Apple USB PCI receive: %w", err)
		}
		if n == 0 {
			return 0, false, nil
		}
	}
}

func (d *appleUSBPCI) transmit(parts []virtioBuffer, length int) (uint32, bool, error) {
	if length < 2 {
		return 0, false, fmt.Errorf("Apple USB PCI: transmit buffer shorter than header")
	}
	packet := make([]byte, length+4)
	at := 4
	for _, part := range parts {
		at += copy(packet[at:], part.data)
	}
	binary.LittleEndian.PutUint32(packet, uint32(length-2))
	packet[4], packet[5] = packet[5], packet[4]
	n, err := d.host.Write(packet)
	if errors.Is(err, channel.ErrWouldBlock) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("Apple USB PCI transmit: %w", err)
	}
	if n != len(packet) {
		return 0, false, io.ErrShortWrite
	}
	if d.emit != nil {
		prefix := append([]byte{packet[5], packet[4]}, packet[6:min(len(packet), 68)]...)
		d.emit("apple.usb_transmit", map[string]any{"prefix": fmt.Sprintf("%x", prefix), "length": length})
	}
	return 0, true, nil // The transmit chain contains no writable bytes.
}
