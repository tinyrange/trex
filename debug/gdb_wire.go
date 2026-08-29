package debug

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	channelpkg "github.com/tinyrange/trex/channel"
)

const (
	defaultGDBPacketSize = 4096
	maximumGDBPacketSize = 16 << 20
	maximumGDBXMLSize    = 8 << 20
)

type gdbWire struct {
	channel    channelpkg.ByteChannel
	noAck      bool
	packetSize int
}

func newGDBWire(channel channelpkg.ByteChannel) *gdbWire {
	return &gdbWire{channel: channel, packetSize: defaultGDBPacketSize}
}

func (w *gdbWire) exchange(payload []byte) ([]byte, error) {
	if err := w.send(payload); err != nil {
		return nil, err
	}
	return w.read()
}

func (w *gdbWire) send(payload []byte) error {
	if len(payload) > w.packetSize {
		return fmt.Errorf("GDB packet size %d exceeds negotiated limit %d", len(payload), w.packetSize)
	}
	escaped := make([]byte, 0, len(payload)+8)
	for _, value := range payload {
		switch value {
		case '#', '$', '}', '*':
			escaped = append(escaped, '}', value^0x20)
		default:
			escaped = append(escaped, value)
		}
	}
	checksum := byte(0)
	for _, value := range escaped {
		checksum += value
	}
	packet := make([]byte, 0, len(escaped)+4)
	packet = append(packet, '$')
	packet = append(packet, escaped...)
	packet = append(packet, '#', "0123456789abcdef"[checksum>>4], "0123456789abcdef"[checksum&15])
	if err := writeAll(w.channel, packet); err != nil {
		return err
	}
	if w.noAck {
		return nil
	}
	ack := []byte{0}
	if _, err := io.ReadFull(w.channel, ack); err != nil {
		return err
	}
	if ack[0] != '+' {
		return fmt.Errorf("GDB target rejected packet with acknowledgement %#x", ack[0])
	}
	return nil
}

func (w *gdbWire) read() ([]byte, error) {
	for {
		leader := []byte{0}
		if _, err := io.ReadFull(w.channel, leader); err != nil {
			return nil, err
		}
		if leader[0] == '+' || leader[0] == '-' {
			continue
		}
		if leader[0] != '$' {
			continue
		}
		break
	}
	encoded := make([]byte, 0, 256)
	for {
		value := []byte{0}
		if _, err := io.ReadFull(w.channel, value); err != nil {
			return nil, err
		}
		if value[0] == '#' {
			break
		}
		encoded = append(encoded, value[0])
		if len(encoded) > w.packetSize+1024 {
			return nil, fmt.Errorf("GDB reply exceeds negotiated packet limit")
		}
	}
	checksumText := make([]byte, 2)
	if _, err := io.ReadFull(w.channel, checksumText); err != nil {
		return nil, err
	}
	want, err := strconv.ParseUint(string(checksumText), 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid GDB checksum: %w", err)
	}
	got := byte(0)
	for _, value := range encoded {
		got += value
	}
	if got != byte(want) {
		if !w.noAck {
			_ = writeAll(w.channel, []byte{'-'})
		}
		return nil, fmt.Errorf("GDB checksum mismatch: got %02x want %02x", got, want)
	}
	if !w.noAck {
		if err := writeAll(w.channel, []byte{'+'}); err != nil {
			return nil, err
		}
	}
	decoded := make([]byte, 0, len(encoded))
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

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

type gdbTargetDescription struct {
	XMLName      xml.Name
	Architecture string           `xml:"architecture"`
	Features     []gdbFeature     `xml:"feature"`
	Includes     []gdbInclude     `xml:"include"`
	Registers    []gdbXMLRegister `xml:"reg"`
}

type gdbFeature struct {
	Registers []gdbXMLRegister `xml:"reg"`
	Includes  []gdbInclude     `xml:"include"`
}

type gdbInclude struct {
	Href string `xml:"href,attr"`
}

type gdbXMLRegister struct {
	Name    string `xml:"name,attr"`
	Bitsize int    `xml:"bitsize,attr"`
	Regnum  *int   `xml:"regnum,attr"`
	Type    string `xml:"type,attr"`
	Group   string `xml:"group,attr"`
}

type gdbRegister struct {
	Name   string
	Number int
	Bits   int
	Offset int
	Type   string
	Group  string
}

func (w *gdbWire) readAnnex(annex string) ([]byte, error) {
	var result bytes.Buffer
	chunkSize := w.packetSize - 128
	if chunkSize < 256 {
		chunkSize = 256
	}
	for offset := 0; ; {
		request := fmt.Sprintf("qXfer:features:read:%s:%x,%x", annex, offset, chunkSize)
		reply, err := w.exchange([]byte(request))
		if err != nil {
			return nil, err
		}
		if len(reply) == 0 || reply[0] != 'm' && reply[0] != 'l' {
			return nil, fmt.Errorf("GDB target rejected feature annex %q: %q", annex, reply)
		}
		if result.Len()+len(reply)-1 > maximumGDBXMLSize {
			return nil, fmt.Errorf("GDB target XML exceeds %d bytes", maximumGDBXMLSize)
		}
		result.Write(reply[1:])
		offset += len(reply) - 1
		if reply[0] == 'l' {
			return result.Bytes(), nil
		}
	}
}

func (w *gdbWire) targetDescription() (string, []gdbRegister, error) {
	seen := make(map[string]bool)
	architecture := ""
	var xmlRegisters []gdbXMLRegister
	var load func(string) error
	load = func(annex string) error {
		if seen[annex] {
			return nil
		}
		seen[annex] = true
		data, err := w.readAnnex(annex)
		if err != nil {
			return err
		}
		var target gdbTargetDescription
		if err := xml.Unmarshal(data, &target); err != nil {
			return fmt.Errorf("parse GDB target XML %q: %w", annex, err)
		}
		if target.Architecture != "" {
			architecture = target.Architecture
		}
		xmlRegisters = append(xmlRegisters, target.Registers...)
		for _, feature := range target.Features {
			xmlRegisters = append(xmlRegisters, feature.Registers...)
			for _, include := range feature.Includes {
				if err := load(include.Href); err != nil {
					return err
				}
			}
		}
		for _, include := range target.Includes {
			if err := load(include.Href); err != nil {
				return err
			}
		}
		return nil
	}
	if err := load("target.xml"); err != nil {
		return "", nil, err
	}
	registers := make([]gdbRegister, 0, len(xmlRegisters))
	number, offset := 0, 0
	for _, register := range xmlRegisters {
		if register.Regnum != nil {
			number = *register.Regnum
		}
		if register.Name == "" || register.Bitsize <= 0 || register.Bitsize%8 != 0 {
			return "", nil, fmt.Errorf("invalid GDB register description for %q", register.Name)
		}
		registers = append(registers, gdbRegister{Name: register.Name, Number: number, Bits: register.Bitsize, Offset: offset, Type: register.Type, Group: register.Group})
		offset += register.Bitsize / 8
		number++
	}
	return architecture, registers, nil
}

func parseGDBFeatures(reply []byte) map[string]string {
	features := make(map[string]string)
	for _, field := range strings.Split(string(reply), ";") {
		if field == "" {
			continue
		}
		if strings.HasSuffix(field, "+") || strings.HasSuffix(field, "-") {
			features[field[:len(field)-1]] = field[len(field)-1:]
		} else if name, value, ok := strings.Cut(field, "="); ok {
			features[name] = value
		} else {
			features[field] = ""
		}
	}
	return features
}

func decodeGDBHex(reply []byte, maximum int) ([]byte, error) {
	if len(reply)%2 != 0 || len(reply)/2 > maximum {
		return nil, fmt.Errorf("invalid or oversized GDB hexadecimal reply")
	}
	data := make([]byte, len(reply)/2)
	if _, err := hex.Decode(data, reply); err != nil {
		return nil, err
	}
	return data, nil
}
