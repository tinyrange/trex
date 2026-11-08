package ckd

import (
	"bytes"
	"fmt"
)

// Decoded fields of the CP object directory. Every field here was checked
// against USER DIRECT source on z/VM 4.4 ADCD media; option bits are listed
// only where a single bit predicted every user. Undecoded bytes remain in
// CPUser.Block and CPDevice.Raw.
//
// User block (0x220 bytes): 0x00-0x03 flags (byte 3: machine mode, X'20'
// NOLOG password), 0x08/0x0C default/maximum storage in bytes, 0x10
// distribution code, 0x18 encoded password (salted by user ID; not decoded),
// 0x20 account, 0x60 eight AUTOLOG/XAUTOLOG user IDs, 0xA5 IPL statement text
// (71 bytes), 0xEC/0xF4 NAMESAVE chain (page, offset), 0xF0/0xF6 IUCV chain,
// 0xF8 MAXCONN, 0xFA SHARE ABSOLUTE, 0xFC/0xFE SHARE RELATIVE, 0x110 user ID,
// 0x118 ACIGROUP, 0x12C privilege classes (bit 31 = A), 0x1A0/0x1A4 POSIX
// UID/GID (X'FFFFFFFF' none), 0x1A8 POSIX group name, 0x1CC/0x1D4
// default/maximum storage in KB, 0x1ED password date (YYMMDD), 0x1F8 INCLUDE
// profile, 0x200 own device count.
//
// IUCV entries (32 bytes): target 0, next page 8 and offset 12, MSGLIMIT 14,
// byte 16 X'80' PRIORITY, byte 17 *IDENT flags (X'80' GATEWAY, X'40' GLOBAL,
// X'20' LOCAL, X'02' REVOKE, X'01' always set), resource name 24. NAMESAVE
// entries (16 bytes): next page 0 and offset 4, name 8.
//
// Device blocks: next device of the user's configuration at 0x38 (page) and
// 0x3C (offset); the chain lists the user's own devices, then those of its
// INCLUDEd profile, ending at zero. Unit-record (type X'08') devices have the
// device class/type halfword at 4 (X'8040' 3215, X'4080' 3270, X'2082' 2540
// reader, X'2042' 2540 punch, X'2021' 1403) and the spool class at 0x18;
// DEDICATE (X'10') blocks hold the real device at 26. MDISK byte 16 flags
// read/write/multi passwords (X'80'/X'40'/X'20', encoded at 0x18/0x20/0x28)
// and byte 17, like the LINK mode halfword at 16, is a mode code.
//
// The directory header is the page after the root index: title "DIRECTORY
// HEADER", root 0x18, POSIX UID index 0x1C, POSIX GID index 0x20, first
// user-block and device pages 0x28/0x2C, and from 0x20 a table of 32-byte
// profile entries in the leaf-entry layout (the first entry's leading word is
// the GID index pointer); profile device blocks are owned by "SYSTEM". GID
// index entries (22 bytes from 0x18): GID, group name, a word and a pointer
// (page, offset) to a 32-byte "DGR" record.

var cpHeaderTitle = []byte{0xc4, 0xc9, 0xd9, 0xc5, 0xc3, 0xe3, 0xd6, 0xd9, 0xe8, 0x40, 0xc8, 0xc5, 0xc1, 0xc4, 0xc5, 0xd9} // "DIRECTORY HEADER"

var cpSystemOwner = []byte{0xe2, 0xe8, 0xe2, 0xe3, 0xc5, 0xd4, 0x40, 0x40} // "SYSTEM", owner of profile devices

var cpModes = map[byte]string{0x00: "R", 0x04: "RR", 0x10: "WR", 0x1c: "M", 0x20: "MR", 0x24: "MW"}

var cpMachines = map[byte]string{0x06: "XA", 0x0c: "ESA", 0x14: "XC"}

var cpOptionBits = []struct {
	Name   string
	Offset int
	Mask   byte
}{
	{"QUICKDSP", 0x02, 0x02}, {"CONCEAL", 0x02, 0x04}, {"ACCT", 0x02, 0x08},
	{"MAINTCCW", 0xa3, 0x02}, {"DEVINFO", 0xa3, 0x08}, {"APPLMON", 0xa3, 0x10}, {"D84NOPAS", 0xa3, 0x20},
	{"SVMSTAT", 0xa4, 0x40}, {"DIAG88", 0x15b, 0x20}, {"LNKNOPAS", 0x21d, 0x40},
}

type CPIUCV struct {
	Target, Resource string
	MessageLimit     uint16
	Priority         bool
	IdentFlags       byte
}

type CPUserFields struct {
	Distribution, Account, ACIGroup, Include, IPL string
	PasswordDate                                  string
	Autolog                                       []string
	Machine                                       string
	NoLog                                         bool
	Classes                                       uint32
	StorageKB, MaximumStorageKB                   uint32
	MaxConn, ShareAbsolute, ShareRelative         uint16
	POSIXUID, POSIXGID                            uint32
	POSIXGroup                                    string
	Options                                       []string
}

func cpText(b []byte) string { return string(bytes.TrimRight([]byte(ebcdicText(b)), " \x00")) }

// ebcdicText decodes common EBCDIC (cp037) printable characters, escaping
// others as Identifier does.
func ebcdicText(b []byte) string {
	var out []byte
	for _, c := range b {
		switch {
		case c == 0x00:
			out = append(out, 0)
		case c == 0x40:
			out = append(out, ' ')
		case c >= 0x81 && c <= 0x89, c >= 0x91 && c <= 0x99, c >= 0xa2 && c <= 0xa9:
			out = append(out, Identifier([]byte{c})...)
		case c == 0x61:
			out = append(out, '/')
		case c == 0x7a:
			out = append(out, ':')
		case c == 0x7e:
			out = append(out, '=')
		case c == 0x5c:
			out = append(out, '*')
		case c == 0x4e:
			out = append(out, '+')
		case c == 0x6b:
			out = append(out, ',')
		case c == 0x7d:
			out = append(out, '\'')
		default:
			out = append(out, Identifier([]byte{c})...)
		}
	}
	return string(out)
}

func decodeCPUserFields(b []byte) CPUserFields {
	f := CPUserFields{Distribution: cpText(b[0x10:0x18]), Account: cpText(b[0x20:0x28]), ACIGroup: cpText(b[0x118:0x120]),
		Include: cpText(b[0x1f8:0x200]), IPL: cpText(b[0xa5 : 0xa5+71]), PasswordDate: cpText(b[0x1ed:0x1f3]),
		Machine: cpMachines[b[3]&^0x20], NoLog: b[3]&0x20 != 0, Classes: be.Uint32(b[0x12c:]),
		StorageKB: be.Uint32(b[0x1cc:]), MaximumStorageKB: be.Uint32(b[0x1d4:]),
		MaxConn: be.Uint16(b[0xf8:]), ShareAbsolute: be.Uint16(b[0xfa:]), ShareRelative: be.Uint16(b[0xfc:]),
		POSIXUID: be.Uint32(b[0x1a0:]), POSIXGID: be.Uint32(b[0x1a4:]), POSIXGroup: cpText(b[0x1a8:0x1b0])}
	for k := 0; k < 8; k++ {
		if n := cpText(b[0x60+8*k : 0x68+8*k]); n != "" {
			f.Autolog = append(f.Autolog, n)
		}
	}
	for _, o := range cpOptionBits {
		if b[o.Offset]&o.Mask != 0 {
			f.Options = append(f.Options, o.Name)
		}
	}
	return f
}

// cpChain follows (page, offset) chains of fixed-size entries.
func (c *CPDirectory) cpChain(ptr uint32, off uint16, size int, nextPage, nextOff int, limit int) ([][]byte, error) {
	var out [][]byte
	seen := map[uint64]bool{}
	for ptr != 0 {
		key := uint64(ptr)<<16 | uint64(off)
		if seen[key] || len(out) == limit {
			return nil, fmt.Errorf("cp directory: chain loops or exceeds %d entries", limit)
		}
		seen[key] = true
		p, err := c.page(ptr)
		if err != nil {
			return nil, err
		}
		if int(off)+size > len(p) {
			return nil, fmt.Errorf("cp directory: chain entry crosses its page")
		}
		e := p[off : int(off)+size]
		out = append(out, e)
		ptr, off = be.Uint32(e[nextPage:]), be.Uint16(e[nextOff:])
	}
	return out, nil
}

// decodeUserExtras fills fields, chains and the resolved configuration.
func (c *CPDirectory) decodeUserExtras(u *CPUser) error {
	u.Fields = decodeCPUserFields(u.Block)
	b := u.Block
	iucv, err := c.cpChain(be.Uint32(b[0xf0:]), be.Uint16(b[0xf6:]), 32, 8, 12, 4096)
	if err != nil {
		return fmt.Errorf("%s IUCV: %w", u.Name, err)
	}
	for _, e := range iucv {
		u.IUCV = append(u.IUCV, CPIUCV{Target: cpText(e[0:8]), Resource: cpText(e[24:32]), MessageLimit: be.Uint16(e[14:]), Priority: e[16]&0x80 != 0, IdentFlags: e[17]})
	}
	names, err := c.cpChain(be.Uint32(b[0xec:]), be.Uint16(b[0xf4:]), 16, 0, 4, 4096)
	if err != nil {
		return fmt.Errorf("%s NAMESAVE: %w", u.Name, err)
	}
	for _, e := range names {
		u.NameSave = append(u.NameSave, cpText(e[8:16]))
	}
	config, err := c.cpChain(u.DevicePage, u.DeviceOffset, 80, 0x38, 0x3c, 65536)
	if err != nil {
		return fmt.Errorf("%s configuration: %w", u.Name, err)
	}
	for _, e := range config {
		if !bytes.Equal(e[0x44:0x48], cpDeviceMark) {
			return fmt.Errorf("cp directory: %s configuration entry is not a device block", u.Name)
		}
		u.Configuration = append(u.Configuration, decodeCPDevice(e))
	}
	// The configuration starts with the user's own devices.
	if len(u.Configuration) < len(u.Devices) {
		return fmt.Errorf("cp directory: %s configuration shorter than its own devices", u.Name)
	}
	for i, d := range u.Devices {
		if !bytes.Equal(u.Configuration[i].Raw, d.Raw) {
			return fmt.Errorf("cp directory: %s configuration does not begin with its own devices", u.Name)
		}
	}
	return nil
}

type CPGroup struct {
	GID  uint32
	Name string
}

// decodeHeader reads the directory header after the root: profiles and POSIX
// groups.
func (c *CPDirectory) decodeHeader(maxUsers int) error {
	ptr := c.next(c.Root)
	h, err := c.page(ptr)
	if err != nil {
		return err
	}
	if !bytes.Equal(h[8:24], cpHeaderTitle) || be.Uint32(h[0x18:]) != c.Root {
		return fmt.Errorf("cp directory: page after the root is not its directory header")
	}
	c.Header = ptr
	for k := 0x20; k+32 <= len(h); k += 32 {
		e := h[k : k+32]
		if bytes.Equal(e[16:24], make([]byte, 8)) {
			break
		}
		entry := append([]byte(nil), e...)
		if k == 0x20 {
			copy(entry[:4], make([]byte, 4)) // shares the GID index pointer
		}
		u, err := c.userOwned(entry, cpSystemOwner)
		if err != nil {
			return fmt.Errorf("profile: %w", err)
		}
		if err := c.decodeUserExtras(&u); err != nil {
			return err
		}
		c.Profiles = append(c.Profiles, u)
	}
	if gid := be.Uint32(h[0x20:]); gid != 0 {
		g, err := c.page(gid)
		if err != nil {
			return err
		}
		n := int(be.Uint16(g[4:]))
		if 0x18+22*n > len(g) || n > maxUsers {
			return fmt.Errorf("cp directory: invalid GID index count %d", n)
		}
		for i := 0; i < n; i++ {
			e := g[0x18+22*i:]
			c.Groups = append(c.Groups, CPGroup{GID: be.Uint32(e), Name: cpText(e[4:12])})
		}
	}
	return nil
}

// ModeName returns the access mode of an MDISK or LINK device.
func (d CPDevice) ModeName() string {
	switch {
	case d.Type&0x80 != 0:
		return cpModes[d.Raw[17]]
	case d.Type&0x40 != 0:
		return cpModes[byte(d.LinkMode)]
	}
	return ""
}
