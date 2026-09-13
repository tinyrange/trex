package dmr

import "fmt"

const GlobalizationTag uint32 = 0x424f4c47 // GLOB

// Globalization records ApplicationProperty choices for one package-relative
// application ID. The native writer emits it even when both choices are false.
type Globalization struct {
	ApplicationID                string
	UTF8, WindowsDisplayLanguage bool
}

func EncodeGlobalization(g Globalization) ([]byte, error) {
	name, err := identityString(g.ApplicationID)
	if err != nil {
		return nil, err
	}
	if len(name) == 0 {
		return nil, fmt.Errorf("dmr: globalization requires an application ID")
	}
	size := 20 + len(name)
	out := make([]byte, align4(size))
	le.PutUint32(out, GlobalizationTag)
	le.PutUint32(out[4:], uint32(size))
	var flags uint32
	if g.UTF8 {
		flags |= 1
	}
	if g.WindowsDisplayLanguage {
		flags |= 2
	}
	le.PutUint32(out[8:], flags)
	le.PutUint32(out[12:], uint32(len(name)))
	copy(out[20:], name)
	return out, nil
}

func ParseGlobalization(data []byte) (Globalization, error) {
	var g Globalization
	if len(data) < 20 || le.Uint32(data) != GlobalizationTag || le.Uint32(data[16:]) != 0 {
		return g, fmt.Errorf("dmr: invalid globalization header")
	}
	size, n, flags := uint64(le.Uint32(data[4:])), uint64(le.Uint32(data[12:])), le.Uint32(data[8:])
	if n == 0 || size != 20+n || (size+3)&^uint64(3) != uint64(len(data)) || flags & ^uint32(3) != 0 {
		return g, fmt.Errorf("dmr: invalid globalization extent/flags")
	}
	if !zeroBytes(data[int(size):]) {
		return g, fmt.Errorf("dmr: nonzero globalization padding")
	}
	name, err := parseIdentityString(data[20:int(size)])
	if err != nil {
		return g, err
	}
	if name == "" {
		return g, fmt.Errorf("dmr: empty globalization application ID")
	}
	return Globalization{ApplicationID: name, UTF8: flags&1 != 0, WindowsDisplayLanguage: flags&2 != 0}, nil
}
