package cc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/channel"
)

// apple-usb channels use little-endian u32 payload length, endpoint byte,
// operation byte, then payload, in both directions. The guest transmit queue
// omits the length and orders operation before endpoint; the bridge normalizes
// that header. Packet boundaries survive byte-channel fragmentation.
const appleUSBPayloadLimit = 1 << 20

func (d *appleSimpleUSB) submitUSB(address uint64) error {
	if d.usbQueue > 1 || d.usbBusy[d.usbQueue] {
		return fmt.Errorf("apple USB: invalid or overlapping queue submission")
	}
	chain, err := d.descriptors(address)
	if err != nil {
		return err
	}
	if d.usbQueue == 0 {
		if len(chain) != 1 || chain[0].flags != 2 || len(chain[0].data) != appleUSBPayloadLimit+6 || d.usbRX != 0 {
			return fmt.Errorf("apple USB: invalid or overlapping receive request")
		}
		d.usbRX = address
		d.usbBusy[0] = true
		return nil
	}
	var packet []byte
	for _, desc := range chain {
		if desc.flags&2 != 0 || len(desc.data) > appleUSBPayloadLimit+2-len(packet) {
			return fmt.Errorf("apple USB: invalid transmit descriptor")
		}
		packet = append(packet, desc.data...)
	}
	if len(packet) < 2 {
		return fmt.Errorf("apple USB: invalid transmit packet length")
	}
	if d.usb == nil {
		return fmt.Errorf("apple USB: transmit without connected host")
	}
	framed := make([]byte, len(packet)+4)
	binary.LittleEndian.PutUint32(framed, uint32(len(packet)-2))
	framed[4], framed[5] = packet[1], packet[0]
	copy(framed[6:], packet[2:])
	d.usbTX, d.usbOutput, d.usbBusy[1] = chain, framed, true
	return d.pollUSBTX()
}

func (d *appleSimpleUSB) pollUSBTX() error {
	if d.usbTX == nil {
		return nil
	}
	for _, desc := range d.usbTX {
		if _, err := d.dmaMemory(desc.address, 16, true); err != nil {
			return err
		}
	}
	if _, err := d.usb.Write(d.usbOutput); err != nil {
		if errors.Is(err, channel.ErrWouldBlock) {
			return nil
		}
		return fmt.Errorf("apple USB transmit: %w", err)
	}
	for _, desc := range d.usbTX {
		binary.LittleEndian.PutUint16(desc.record[12:], 0)
	}
	d.usbBusy[1] = false
	packet := append([]byte{d.usbOutput[5], d.usbOutput[4]}, d.usbOutput[6:]...)
	d.emit("apple.usb_transmit", map[string]any{"prefix": fmt.Sprintf("%x", packet[:min(64, len(packet))]), "length": len(packet)})
	d.usbTX, d.usbOutput = nil, nil
	return nil
}

func (d *appleSimpleUSB) pollUSB() error {
	if err := d.pollUSBTX(); err != nil {
		return err
	}
	if d.usb == nil || d.usbRX == 0 {
		return nil
	}
	want := 6
	if len(d.usbInput) >= 6 {
		length := binary.LittleEndian.Uint32(d.usbInput)
		if length > appleUSBPayloadLimit {
			return fmt.Errorf("apple USB: host packet exceeds payload limit")
		}
		want += int(length)
	}
	if len(d.usbInput) < want {
		var buffer [4096]byte
		n, err := d.usb.Read(buffer[:min(len(buffer), want-len(d.usbInput))])
		if err != nil && !errors.Is(err, channel.ErrWouldBlock) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
		d.usbInput = append(d.usbInput, buffer[:n]...)
		if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)) && len(d.usbInput) != 0 && len(d.usbInput) < want {
			return io.ErrUnexpectedEOF
		}
	}
	if len(d.usbInput) < 6 {
		return nil
	}
	length := binary.LittleEndian.Uint32(d.usbInput)
	if length > appleUSBPayloadLimit {
		return fmt.Errorf("apple USB: host packet exceeds payload limit")
	}
	if len(d.usbInput) != int(length)+6 {
		return nil
	}
	chain, err := d.descriptors(d.usbRX)
	if err != nil {
		return err
	}
	if len(chain) != 1 || chain[0].flags != 2 || len(chain[0].data) != appleUSBPayloadLimit+6 {
		return fmt.Errorf("apple USB: receive descriptor changed while pending")
	}
	copy(chain[0].data, d.usbInput)
	binary.LittleEndian.PutUint16(chain[0].record[12:], 0)
	d.emit("apple.usb_receive", map[string]any{"endpoint": d.usbInput[4], "operation": d.usbInput[5], "length": length})
	d.usbRX, d.usbInput, d.usbBusy[0] = 0, nil, false
	return nil
}
