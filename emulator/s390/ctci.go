package s390

// CTCI is a 3088 channel-to-channel adapter carrying IP, as TCP/IP stacks
// drive a "CTC" device: a pair of subchannels at an even device number and
// the next. Programs differ in which of the two they read, so either may
// read or write. Each block on the wire is a 2-byte
// big-endian offset of the block's end, then segments of a 6-byte header
// (2-byte length including the header, 2-byte type X'0800', 2 reserved
// bytes) and one IP packet each, and finally a zero offset ending the
// chain. A READ waits until a packet arrives; a write whose first offset
// is zero is an initialization block and carries nothing.
type CTCI struct {
	css     *ChannelSubsystem
	read    uint16
	queue   [][]byte
	queued  int
	version uint64
	// Out receives each IP packet the program sends. It runs while the
	// machine executes and must not block.
	Out func(packet []byte)
	// Packets counts packets in each direction.
	Sent, Received uint64
	// Outbox keeps the latest packets sent while Out is not set.
	Outbox [][]byte
}

const ctciBlockLimit = 0x5000

type ctciSide struct {
	c     *CTCI
	write bool
	sense byte
}

// AttachCTCI attaches a CTC adapter at devno (read) and devno+1 (write).
func (s *ChannelSubsystem) AttachCTCI(devno uint16) (*CTCI, error) {
	if devno&1 != 0 {
		return nil, errOddCTC
	}
	c := &CTCI{css: s, read: devno}
	if _, err := s.Attach(devno, &ctciSide{c: c}); err != nil {
		return nil, err
	}
	if _, err := s.Attach(devno+1, &ctciSide{c: c, write: true}); err != nil {
		return nil, err
	}
	return c, nil
}

var errOddCTC = errorString("ctc: the read device number must be even")

type errorString string

func (e errorString) Error() string { return string(e) }

// Deliver queues an IP packet for the program and completes a READ that
// is waiting for one. It must run between execution slices.
func (c *CTCI) Deliver(packet []byte) {
	if len(packet) == 0 || len(packet) > ctciBlockLimit-12 {
		return
	}
	if c.queued > 1<<20 {
		return // the program is not reading: drop, as a full adapter does
	}
	c.queue = append(c.queue, append([]byte(nil), packet...))
	c.queued += len(packet)
	c.Received++
	c.version++
	if c.css != nil && !c.css.Resume(c.read) {
		c.css.Resume(c.read + 1)
	}
}

func (d *ctciSide) SenseID() []byte {
	return []byte{0xff, 0x30, 0x88, 0x08, 0x30, 0x88, 0x01}
}

func (d *ctciSide) Reset() { d.sense = 0 }

// Blocked reports whether a READ must wait for a packet.
func (d *ctciSide) Blocked(cmd byte) bool {
	return (cmd&3 == 2 || cmd&0x0f == 0x0c) && len(d.c.queue) == 0
}

func (d *ctciSide) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	switch {
	case cmd == 0x04: // sense
		s := d.sense
		d.sense = 0
		return []byte{s}, 0, usCE | usDE
	case cmd == 0xe4:
		return d.SenseID(), 0, usCE | usDE
	case cmd&7 == 7, cmd&0x47 == 3, cmd == 0xc3, cmd == 0xe3, cmd&0x1f == 0x14, cmd&0xc7 == 0x43:
		// control, no-operation, set extended/basic mode, prepare, SCB
		return nil, len(data), usCE | usDE
	case cmd&3 == 2 || cmd&0x0f == 0x0c: // read, read backward
		// The channel trims the block to the CCW count.
		return d.readBlock(), 0, usCE | usDE
	case cmd&3 == 1: // write
		return nil, len(data), d.writeBlock(data)
	}
	d.sense = 0x80 // command reject
	return nil, 0, usCE | usDE | usUnitCheck
}

// readBlock builds one block of queued packets.
func (d *ctciSide) readBlock() []byte {
	c := d.c
	limit := ctciBlockLimit
	out := []byte{0, 0}
	for len(c.queue) > 0 {
		p := c.queue[0]
		if len(out)+6+len(p)+2 > limit && len(out) > 2 {
			break
		}
		n := 6 + len(p)
		out = append(out, byte(n>>8), byte(n), 0x08, 0x00, 0, 0)
		out = append(out, p...)
		c.queue = c.queue[1:]
		c.queued -= len(p)
	}
	end := len(out)
	out[0], out[1] = byte(end>>8), byte(end)
	out = append(out, 0, 0) // end of the chain
	c.version++
	return out
}

// writeBlock passes each IP packet of a block to Out.
func (d *ctciSide) writeBlock(data []byte) byte {
	if len(data) < 2 {
		d.sense = 0x08 // data check
		return usCE | usDE | usUnitCheck
	}
	end := int(data[0])<<8 | int(data[1])
	if end == 0 {
		return usCE | usDE // initialization block
	}
	if end > len(data) {
		d.sense = 0x08 // the block runs past the data written
		return usCE | usDE | usUnitCheck
	}
	for pos := 2; pos+6 <= end; {
		n := int(data[pos])<<8 | int(data[pos+1])
		if n < 6 || pos+n > end {
			d.sense = 0x08
			return usCE | usDE | usUnitCheck
		}
		p := append([]byte(nil), data[pos+6:pos+n]...)
		if d.c.Out != nil {
			d.c.Out(p)
		} else {
			if len(d.c.Outbox) >= 256 {
				d.c.Outbox = d.c.Outbox[1:]
			}
			d.c.Outbox = append(d.c.Outbox, p)
		}
		d.c.Sent++
		pos += n
	}
	d.c.version++
	return usCE | usDE
}

// Version changes as packets move, for frontends watching the adapter.
func (c *CTCI) Version() uint64 { return c.version }
