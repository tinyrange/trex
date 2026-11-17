package tn3270

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/emulator/s390"
	"strings"
)

// Client is a transport-independent TN3270 display station. Feed receives
// remote wire bytes and returns wire replies. It owns no socket, CPU, channel
// subsystem or mainframe device; Console3270 is only its presentation space.
// Classic TN3270 and IBM-3278-2-E queries are supported, not TN3270E framing.
type Client struct {
	Display       *s390.Console3270
	state         byte
	verb          byte
	record, sub   []byte
	local, remote [256]bool
	Err           error
	Records       uint64
}

func NewClient() *Client { return &Client{Display: s390.NewConsole3270(24, 80)} }

func frame(data []byte) []byte {
	out := bytes.ReplaceAll(data, []byte{iac}, []byte{iac, iac})
	return append(out, iac, eor)
}

// Feed retains partial Telnet commands, escaped IACs and records between calls.
// A malformed record poisons this client; callers must explicitly create a new
// client rather than silently skipping input. Reply bytes precede any error.
func (c *Client) Feed(data []byte) (out []byte, err error) {
	if c.Err != nil {
		return nil, c.Err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("tn3270: feed exceeds 1 MiB")
	}
	for _, b := range data {
		switch c.state {
		case 0:
			if b == iac {
				c.state = 1
			} else {
				c.record = append(c.record, b)
			}
		case 1:
			switch b {
			case iac:
				c.record = append(c.record, b)
				c.state = 0
			case eor:
				c.state = 0
				if len(c.record) > 0 {
					var response []byte
					response, err = c.receive(c.record)
					out = append(out, response...)
					c.record = c.record[:0]
					if err != nil {
						c.Err = err
						return out, err
					}
				}
			case will, wont, do, dont:
				c.verb = b
				c.state = 2
			case sb:
				c.sub = c.sub[:0]
				c.state = 3
			case nop:
				c.state = 0
			default:
				c.Err = fmt.Errorf("tn3270: unsupported Telnet command %02x", b)
				return out, c.Err
			}
		case 2:
			c.state = 0
			switch c.verb {
			case do:
				if b == optBin || b == optEOR || b == optTType {
					if !c.local[b] {
						out = append(out, iac, will, b)
					}
					c.local[b] = true
				} else {
					out = append(out, iac, wont, b)
				}
			case dont:
				if c.local[b] {
					out = append(out, iac, wont, b)
				}
				c.local[b] = false
			case will:
				if b == optBin || b == optEOR {
					if !c.remote[b] {
						out = append(out, iac, do, b)
					}
					c.remote[b] = true
				} else {
					out = append(out, iac, dont, b)
				}
			case wont:
				if c.remote[b] {
					out = append(out, iac, dont, b)
				}
				c.remote[b] = false
			}
		case 3:
			if b == iac {
				c.state = 4
			} else {
				c.sub = append(c.sub, b)
			}
		case 4:
			if b == iac {
				c.sub = append(c.sub, b)
				c.state = 3
			} else if b == se {
				c.state = 0
				if len(c.sub) == 2 && c.sub[0] == optTType && c.sub[1] == 1 {
					out = append(out, iac, sb, optTType, 0)
					out = append(out, []byte("IBM-3278-2-E")...)
					out = append(out, iac, se)
				} else {
					c.Err = fmt.Errorf("tn3270: unsupported subnegotiation %x", c.sub)
					return out, c.Err
				}
			} else {
				c.Err = fmt.Errorf("tn3270: malformed subnegotiation")
				return out, c.Err
			}
		}
		if len(c.record) > 64<<10 || len(c.sub) > 1024 {
			c.Err = fmt.Errorf("tn3270: record/subnegotiation exceeds limit")
			return out, c.Err
		}
	}
	return out, nil
}

func (c *Client) receive(record []byte) ([]byte, error) {
	c.Records++
	cmd := byte(0)
	// Some classic servers (including original IBM LAN3274) retain local
	// channel command codes rather than their remote EBCDIC counterparts.
	switch record[0] {
	case 0xf1, 0x01:
		cmd = 1
	case 0xf5, 0x05:
		cmd = 5
	case 0x7e, 0x0d:
		cmd = 0x0d
	case 0x6f, 0x0f:
		cmd = 0x0f
	case 0xf3, 0x11:
		cmd = 0x11
	case 0xf2, 0x02:
		cmd = 2
	case 0xf6, 0x06:
		cmd = 6
	case 0x6e, 0x0e:
		cmd = 0x0e
	default:
		return nil, fmt.Errorf("tn3270: unsupported data-stream command %02x (record %d, length %d, prefix %x)", record[0], c.Records, len(record), record[:min(64, len(record))])
	}
	data, _, status := c.Display.Exec(cmd, record[1:], false)
	if status&2 != 0 {
		return nil, fmt.Errorf("tn3270: unsupported/invalid 3270 orders for %02x", record[0])
	}
	if cmd == 2 && len(data) != 0 && data[0] != 0x88 {
		// A remote Read Buffer has no channel chaining position. Retaining the
		// last SBA truncates size-detection replies sent by real TN3270 servers.
		data = c.Display.ReadFullBuffer()
	}
	if cmd == 0x11 { // A WSF query requests a structured-field reply.
		data, _, status = c.Display.Exec(6, nil, false)
		if status&2 != 0 {
			return nil, fmt.Errorf("tn3270: structured-field reply failed")
		}
	}
	if data != nil {
		return frame(data), nil
	}
	return nil, nil
}

func (c *Client) Type(text string) error {
	if c.Err != nil {
		return c.Err
	}
	if c.Display.Locked() {
		return fmt.Errorf("tn3270: keyboard is inhibited")
	}
	if len(text) > 4096 {
		return fmt.Errorf("tn3270: typed text exceeds 4096 bytes")
	}
	return c.Display.Type(text)
}

func (c *Client) Key(name string) ([]byte, error) {
	if c.Err != nil {
		return nil, c.Err
	}
	name = strings.ToUpper(name)
	attention := name == "ENTER" || name == "CLEAR" || strings.HasPrefix(name, "PA") || strings.HasPrefix(name, "PF")
	if attention && c.Display.Locked() && name != "CLEAR" {
		return nil, fmt.Errorf("tn3270: keyboard is inhibited")
	}
	if err := c.Display.Key(name); err != nil {
		return nil, err
	}
	if !attention {
		return nil, nil
	}
	data, _, status := c.Display.Exec(6, nil, false)
	if status&2 != 0 {
		return nil, fmt.Errorf("tn3270: keyboard read failed")
	}
	return frame(data), nil
}
