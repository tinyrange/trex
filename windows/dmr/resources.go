package dmr

import "fmt"

const (
	PackageResourcesTag     uint32 = 0x50534552 // RESP
	ApplicationResourcesTag uint32 = 0x41534552 // RESA
	maxResources                   = 1024
)

// NamedResource preserves the two native u16 fields and its length-delimited
// payload. Payload interpretation belongs to resource resolution, not this
// binary codec: bytes are not assumed to be a terminated UTF-16 string.
type NamedResource struct {
	Value4, Value6 uint16
	Data           []byte
}

// Resources is one RESP or RESA section. Index is the native section index;
// its relationship to the package/application graph must be checked by the
// construction layer. Repeated resource entries retain their original order.
type Resources struct {
	Application bool
	Index       uint16
	Entries     []NamedResource
}

func EncodeResources(resources Resources) ([]byte, error) {
	if resources.Index > 640 || len(resources.Entries) == 0 || len(resources.Entries) > maxResources {
		return nil, fmt.Errorf("dmr: invalid resource index/count")
	}
	out := make([]byte, 16)
	tag := PackageResourcesTag
	if resources.Application {
		tag = ApplicationResourcesTag
	}
	le.PutUint32(out, tag)
	le.PutUint16(out[8:], resources.Index)
	le.PutUint16(out[10:], uint16(len(resources.Entries)))
	for _, entry := range resources.Entries {
		if len(entry.Data) > 65535 {
			return nil, fmt.Errorf("dmr: resource payload exceeds u16 length")
		}
		size := 12 + len(entry.Data)
		offset := len(out)
		out = append(out, make([]byte, align4(size))...)
		le.PutUint32(out[offset:], uint32(size))
		le.PutUint16(out[offset+4:], entry.Value4)
		le.PutUint16(out[offset+6:], entry.Value6)
		le.PutUint16(out[offset+8:], uint16(len(entry.Data)))
		copy(out[offset+12:], entry.Data)
	}
	le.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// ParseResources validates each named-resource record and its alignment bytes.
// Payload slices alias data and have capped capacities; keep data immutable.
func ParseResources(data []byte) (Resources, error) {
	var result Resources
	if len(data) < 16 || len(data) > maxSize || len(data)%4 != 0 ||
		uint64(le.Uint32(data[4:])) != uint64(len(data)) || le.Uint32(data[12:]) != 0 {
		return result, fmt.Errorf("dmr: invalid resource section header")
	}
	switch le.Uint32(data) {
	case PackageResourcesTag:
	case ApplicationResourcesTag:
		result.Application = true
	default:
		return result, fmt.Errorf("dmr: invalid resource section tag")
	}
	result.Index = le.Uint16(data[8:])
	count := int(le.Uint16(data[10:]))
	if result.Index > 640 || count == 0 || count > maxResources {
		return Resources{}, fmt.Errorf("dmr: invalid resource index/count")
	}
	result.Entries = make([]NamedResource, 0, count)
	offset := 16
	for i := 0; i < count; i++ {
		if len(data)-offset < 12 {
			return Resources{}, fmt.Errorf("dmr: missing named resource %d", i)
		}
		size := uint64(le.Uint32(data[offset:]))
		payloadSize := int(le.Uint16(data[offset+8:]))
		aligned := (size + 3) &^ uint64(3)
		if size != uint64(12+payloadSize) || aligned > uint64(len(data)-offset) || le.Uint16(data[offset+10:]) != 0 {
			return Resources{}, fmt.Errorf("dmr: invalid named resource %d extent/header", i)
		}
		end := offset + int(size)
		if !zeroBytes(data[end : offset+int(aligned)]) {
			return Resources{}, fmt.Errorf("dmr: nonzero resource padding")
		}
		result.Entries = append(result.Entries, NamedResource{Value4: le.Uint16(data[offset+4:]), Value6: le.Uint16(data[offset+6:]), Data: data[offset+12 : end : end]})
		offset += int(aligned)
	}
	if offset != len(data) {
		return Resources{}, fmt.Errorf("dmr: trailing resource section bytes")
	}
	return result, nil
}
