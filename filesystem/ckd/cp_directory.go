package ckd

import (
	"bytes"
	"fmt"
)

// CP object directory (DIRECTXA output) on a CP-owned volume. The area is
// CP-formatted 4096-byte pages whose record numbers continue across the
// tracks of a cylinder; a page pointer is a 2-byte cylinder, a 1-byte record
// number and a zero byte. VOL1 offset 0x34 points at the active directory's
// root index page.
//
// Index pages carry a title at 8 ("DIRECTORY INDEX ") and an entry count
// halfword at 4. The root holds 12-byte entries from 0x18 (highest user name,
// leaf pointer); leaves are chained by the pointer in their first word and
// hold 32-byte entries from 0x20: halfword user-block offset at 4, halfword
// device-block offset at 6, user-block page at 8, device-block page at 12,
// name at 16, a flags word at 24 and a word at 28. A user block is 0x220 bytes
// whose halfword at 0x200 counts the user's own device blocks (devices from an
// INCLUDEd profile are not counted). Device blocks are 80 bytes: device
// address 0, type byte 2 (X'80' MDISK, X'40' LINK), "DDEV" and the owning
// user at 0x44. A device stream fills pages with whole blocks and continues
// on the next page, in record order, that begins with the same owner's
// blocks. Decoded from z/VM 4.4 ADCD media; see cp_directory_fields.go for
// user, chain, device and header fields.

var (
	cpIndexTitle = []byte{0xc4, 0xc9, 0xd9, 0xc5, 0xc3, 0xe3, 0xd6, 0xd9, 0xe8, 0x40, 0xc9, 0xd5, 0xc4, 0xc5, 0xe7, 0x40} // "DIRECTORY INDEX "
	cpDeviceMark = []byte{0xc4, 0xc4, 0xc5, 0xe5}                                                                         // "DDEV"
)

const cpUserBlock = 0x220

type CPDevice struct {
	Raw     []byte
	Address uint16
	Type    byte
	Owner   string
	// MDISK fields; Mode is the mode code (see ModeName).
	Start, End uint16
	Volume     string
	Mode       byte
	// LINK fields.
	TargetUser    string
	TargetAddress uint16
	LinkMode      uint16
	// MDISK password flags (X'80' read, X'40' write, X'20' multi).
	PasswordFlags byte
	// Unit-record (type X'08') fields.
	DeviceType uint16
	SpoolClass string
	// DEDICATE (type X'10') real device.
	RealAddress uint16
}

type CPUser struct {
	Name         string
	RawName      []byte
	Flags, Word  uint32
	Block        []byte
	DeviceCount  int
	Devices      []CPDevice
	BlockPage    uint32
	BlockOffset  uint16
	DevicePage   uint32
	DeviceOffset uint16
	Fields       CPUserFields
	IUCV         []CPIUCV
	NameSave     []string
	// Configuration is the user's resolved device chain: its own devices,
	// then those of its INCLUDEd profile.
	Configuration []CPDevice
}

type CPDirectory struct {
	Root, Header uint32
	Users        []CPUser
	Profiles     []CPUser
	Groups       []CPGroup
	disk         *Disk
	per          uint32
}

func (c *CPDirectory) page(ptr uint32) ([]byte, error) {
	cyl, rec := ptr>>16, (ptr>>8)&0xff
	if ptr&0xff != 0 || rec == 0 || rec > c.per*c.disk.Heads {
		return nil, fmt.Errorf("cp directory: invalid page pointer %08x", ptr)
	}
	rs, err := c.disk.Track(cyl*c.disk.Heads + (rec-1)/c.per)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.Number == byte(rec) {
			if len(r.Data) != 4096 || len(r.Key) != 0 {
				return nil, fmt.Errorf("cp directory: page %08x is not a 4096-byte page", ptr)
			}
			return r.Data, nil
		}
	}
	return nil, fmt.Errorf("cp directory: page %08x missing", ptr)
}

// next returns the pointer of the following page in record order.
func (c *CPDirectory) next(ptr uint32) uint32 {
	cyl, rec := ptr>>16, (ptr>>8)&0xff
	if rec == c.per*c.disk.Heads {
		return (cyl+1)<<16 | 1<<8
	}
	return cyl<<16 | (rec+1)<<8
}

// OpenCPDirectory reads the object directory whose root index page is root,
// or, when root is zero, the one selected by the VOL1 label.
func OpenCPDirectory(d *Disk, root uint32, maxUsers int) (*CPDirectory, error) {
	rs, err := d.Track(0)
	if err != nil {
		return nil, err
	}
	if root == 0 {
		for _, r := range rs {
			if len(r.Data) >= 80 && bytes.Equal(r.Data[:4], []byte{0xe5, 0xd6, 0xd3, 0xf1}) {
				root = be.Uint32(r.Data[0x34:])
			}
		}
		if root == 0 {
			return nil, fmt.Errorf("cp directory: VOL1 label has no directory pointer")
		}
	}
	c := &CPDirectory{Root: root, disk: d}
	// CP pages: count the 4096-byte records on the directory's first track.
	first, err := d.Track((root >> 16) * d.Heads)
	if err != nil {
		return nil, err
	}
	for _, r := range first {
		if r.Number > 0 && len(r.Data) == 4096 {
			c.per++
		}
	}
	if c.per == 0 {
		return nil, fmt.Errorf("cp directory: cylinder %d is not CP-formatted", root>>16)
	}
	rp, err := c.page(root)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rp[8:24], cpIndexTitle) {
		return nil, fmt.Errorf("cp directory: root page %08x is not a directory index", root)
	}
	n := int(be.Uint16(rp[4:]))
	if n == 0 || 0x18+12*n > len(rp) {
		return nil, fmt.Errorf("cp directory: invalid root entry count %d", n)
	}
	// The root's children must be the leaf chain in order; each child's last
	// user is the root entry's high key.
	leaf := be.Uint32(rp[0x18+8:])
	seen := map[uint32]bool{}
	for i := 0; i < n; i++ {
		high, ptr := rp[0x18+12*i:0x20+12*i], be.Uint32(rp[0x20+12*i:])
		if ptr != leaf || seen[leaf] {
			return nil, fmt.Errorf("cp directory: root entry %d does not follow the leaf chain", i)
		}
		seen[leaf] = true
		lp, err := c.page(leaf)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(lp[8:24], cpIndexTitle) {
			return nil, fmt.Errorf("cp directory: leaf %08x is not a directory index", leaf)
		}
		m := int(be.Uint16(lp[4:]))
		if m == 0 || 0x20+32*m > len(lp) {
			return nil, fmt.Errorf("cp directory: leaf %08x has invalid count %d", leaf, m)
		}
		for j := 0; j < m; j++ {
			if len(c.Users) == maxUsers {
				return nil, fmt.Errorf("cp directory: users exceed limit %d", maxUsers)
			}
			u, err := c.user(lp[0x20+32*j : 0x40+32*j])
			if err != nil {
				return nil, err
			}
			if err := c.decodeUserExtras(&u); err != nil {
				return nil, err
			}
			c.Users = append(c.Users, u)
		}
		if !bytes.Equal(lp[0x20+32*(m-1)+16:0x20+32*(m-1)+24], high) {
			return nil, fmt.Errorf("cp directory: leaf %08x does not end at root key", leaf)
		}
		leaf = be.Uint32(lp)
	}
	if leaf != 0 {
		return nil, fmt.Errorf("cp directory: leaf chain continues past the root's last entry")
	}
	if err := c.decodeHeader(maxUsers); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CPDirectory) user(e []byte) (CPUser, error) { return c.userOwned(e, nil) }

// userOwned reads an entry whose device blocks name owner (nil: the entry's
// own name; profiles' blocks are owned by "SYSTEM").
func (c *CPDirectory) userOwned(e, owner []byte) (CPUser, error) {
	u := CPUser{RawName: append([]byte(nil), e[16:24]...), Name: Identifier(e[16:24]), Flags: be.Uint32(e[24:]), Word: be.Uint32(e[28:]),
		BlockOffset: be.Uint16(e[4:]), DeviceOffset: be.Uint16(e[6:]), BlockPage: be.Uint32(e[8:]), DevicePage: be.Uint32(e[12:])}
	p, err := c.page(u.BlockPage)
	if err != nil {
		return u, err
	}
	if int(u.BlockOffset)+cpUserBlock > len(p) {
		return u, fmt.Errorf("cp directory: %s user block crosses its page", u.Name)
	}
	u.Block = append([]byte(nil), p[u.BlockOffset:int(u.BlockOffset)+cpUserBlock]...)
	u.DeviceCount = int(be.Uint16(u.Block[0x200:]))
	if owner == nil {
		owner = u.RawName
	}
	ptr, off := u.DevicePage, int(u.DeviceOffset)
	for len(u.Devices) < u.DeviceCount {
		if off+80 > 4096 {
			// Continue on the next page beginning with this owner's blocks.
			found := false
			for k := 0; k < 4096 && !found; k++ {
				ptr = c.next(ptr)
				q, err := c.page(ptr)
				if err != nil {
					return u, fmt.Errorf("cp directory: %s device stream: %w", u.Name, err)
				}
				found = bytes.Equal(q[0x44:0x48], cpDeviceMark) && bytes.Equal(q[0x48:0x50], owner)
			}
			if !found {
				return u, fmt.Errorf("cp directory: %s device stream ends after %d blocks", u.Name, len(u.Devices))
			}
			off = 0
		}
		q, err := c.page(ptr)
		if err != nil {
			return u, err
		}
		b := q[off : off+80]
		if !bytes.Equal(b[0x44:0x48], cpDeviceMark) || !bytes.Equal(b[0x48:0x50], owner) {
			return u, fmt.Errorf("cp directory: %s device block %d belongs to %s", u.Name, len(u.Devices), Identifier(b[0x48:0x50]))
		}
		u.Devices = append(u.Devices, decodeCPDevice(b))
		off += 80
	}
	return u, nil
}

func decodeCPDevice(b []byte) CPDevice {
	d := CPDevice{Raw: append([]byte(nil), b...), Address: be.Uint16(b), Type: b[2], Owner: Identifier(b[0x48:0x50])}
	switch {
	case b[2]&0x80 != 0: // MDISK
		d.Start, d.End, d.Volume, d.Mode, d.PasswordFlags = be.Uint16(b[6:]), be.Uint16(b[8:]), Identifier(b[10:16]), b[17], b[16]
	case b[2]&0x40 != 0: // LINK
		d.TargetUser, d.TargetAddress, d.LinkMode = Identifier(b[32:40]), be.Uint16(b[26:]), be.Uint16(b[16:])
	case b[2] == 0x08: // SPOOL, CONSOLE
		d.DeviceType, d.SpoolClass = be.Uint16(b[4:]), ebcdicText(b[0x18:0x19])
	case b[2] == 0x10: // DEDICATE
		d.RealAddress = be.Uint16(b[26:])
	}
	return d
}
