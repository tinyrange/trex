package dmr

import "fmt"

const (
	TargetPlatformTag uint32 = 0x544c5054 // TPLT
	TrailerTag        uint32 = 0x384e484a // JHN8
)

// TargetPlatform preserves the three native GetPackageTargetPlatformProperty
// selectors, 1..3. Value16 is OSMinVersion and Value24 is OSMaxVersionTested.
// Platform is TargetDeviceFamily.Name, not the database relationship identity.
// This codec applies no host OS defaults or version-order assumptions.
type TargetPlatform struct {
	Platform         uint32
	Value16, Value24 uint64
}

// EncodeTargetPlatform emits the fixed 32-byte TPLT record. Unlike DEPG and
// SECU, offset 4 is reserved zero, not the record's length.
func EncodeTargetPlatform(platform TargetPlatform) []byte {
	out := make([]byte, 32)
	le.PutUint32(out, TargetPlatformTag)
	le.PutUint32(out[12:], platform.Platform)
	le.PutUint64(out[16:], platform.Value16)
	le.PutUint64(out[24:], platform.Value24)
	return out
}

func ParseTargetPlatform(data []byte) (TargetPlatform, error) {
	if len(data) != 32 || le.Uint32(data) != TargetPlatformTag || !zeroBytes(data[4:12]) {
		return TargetPlatform{}, fmt.Errorf("dmr: invalid TPLT record")
	}
	return TargetPlatform{Platform: le.Uint32(data[12:]), Value16: le.Uint64(data[16:]), Value24: le.Uint64(data[24:])}, nil
}

// EncodeTrailer emits the native eight-byte end marker. It contains no size,
// checksum, timestamp, or synthetic package policy.
func EncodeTrailer() []byte {
	out := make([]byte, 8)
	le.PutUint32(out, TrailerTag)
	return out
}

func ParseTrailer(data []byte) error {
	if len(data) != 8 || le.Uint32(data) != TrailerTag || le.Uint32(data[4:]) != 0 {
		return fmt.Errorf("dmr: invalid JHN8 trailer")
	}
	return nil
}
