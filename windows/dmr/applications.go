package dmr

import "fmt"

const ApplicationsTag uint32 = 0x53505041 // APPS
const maxApplications = 100

// Application preserves the native application's fields. Unresolved scalar
// meanings are named by byte offset rather than assigned guessed policy names.
// Strings follow length-field order 8,12,14,16,18,28. ForegroundText is the
// native numeric value from SetForegroundText. Recipe mapping is separate.
type Application struct {
	Value6, Value7          uint8
	Value10                 uint16
	ForegroundText, Value24 uint32
	Strings                 [6]string
	ContentURIRules         []ContentURIRule
}

var applicationStringOffsets = [...]int{8, 12, 14, 16, 18, 28}

func encodeApplication(app Application) ([]byte, error) {
	var fields [6][]byte
	size := 36
	for i, value := range app.Strings {
		b, err := identityString(value)
		if err != nil {
			return nil, err
		}
		fields[i] = b
		size += len(b)
	}
	rules, err := EncodeContentURIRules(app.ContentURIRules)
	if err != nil {
		return nil, err
	}
	size += len(rules)
	out := make([]byte, align4(size))
	le.PutUint32(out, uint32(size))
	out[6], out[7] = app.Value6, app.Value7
	le.PutUint16(out[10:], app.Value10)
	le.PutUint32(out[20:], app.ForegroundText)
	le.PutUint32(out[24:], app.Value24)
	le.PutUint16(out[30:], uint16(len(app.ContentURIRules)))
	le.PutUint32(out[32:], uint32(len(rules)))
	offset := 36
	for i, field := range fields {
		le.PutUint16(out[applicationStringOffsets[i]:], uint16(len(field)))
		copy(out[offset:], field)
		offset += len(field)
	}
	copy(out[offset:], rules)
	return out, nil
}

func parseApplication(data []byte) (Application, error) {
	var app Application
	if len(data) < 36 {
		return app, fmt.Errorf("dmr: short application")
	}
	size := uint64(le.Uint32(data))
	if size < 36 || (size+3)&^uint64(3) != uint64(len(data)) || le.Uint16(data[4:]) != 0 {
		return app, fmt.Errorf("dmr: invalid application extent/header")
	}
	if !zeroBytes(data[int(size):]) {
		return app, fmt.Errorf("dmr: nonzero application padding")
	}
	var lengths [6]int
	total := uint64(36)
	for i, offset := range applicationStringOffsets {
		lengths[i] = int(le.Uint16(data[offset:]))
		total += uint64(lengths[i])
	}
	ruleSize := uint64(le.Uint32(data[32:]))
	if ruleSize > 65534 || total+ruleSize != size {
		return app, fmt.Errorf("dmr: invalid application payload extents")
	}
	offset := 36
	for i, n := range lengths {
		value, err := parseIdentityString(data[offset : offset+n])
		if err != nil {
			return Application{}, err
		}
		app.Strings[i] = value
		offset += n
	}
	rules, err := ParseContentURIRules(data[offset:int(size)], le.Uint16(data[30:]))
	if err != nil {
		return Application{}, err
	}
	app.Value6, app.Value7 = data[6], data[7]
	app.Value10 = le.Uint16(data[10:])
	app.ForegroundText, app.Value24 = le.Uint32(data[20:]), le.Uint32(data[24:])
	app.ContentURIRules = rules
	return app, nil
}

// EncodeApplications encodes an explicitly supplied ordered APPS section.
// A package with no applications must omit this section, not emit an empty list.
func EncodeApplications(apps []Application) ([]byte, error) {
	if len(apps) == 0 || len(apps) > maxApplications {
		return nil, fmt.Errorf("dmr: APPS requires 1..%d applications", maxApplications)
	}
	out := make([]byte, 16)
	le.PutUint32(out, ApplicationsTag)
	le.PutUint32(out[12:], uint32(len(apps)))
	for i, app := range apps {
		b, err := encodeApplication(app)
		if err != nil {
			return nil, fmt.Errorf("dmr: application %d: %w", i, err)
		}
		out = append(out, b...)
	}
	le.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// ParseApplications validates the APPS envelope, every application record, and
// its independently length-delimited content-URI payload. It does not prove
// that the records represent valid registration policy or matching package IDs.
func ParseApplications(data []byte) ([]Application, error) {
	if len(data) < 16 || len(data) > maxSize || len(data)%4 != 0 || le.Uint32(data) != ApplicationsTag ||
		uint64(le.Uint32(data[4:])) != uint64(len(data)) || le.Uint32(data[8:]) != 0 {
		return nil, fmt.Errorf("dmr: invalid APPS header")
	}
	count := le.Uint32(data[12:])
	if count == 0 || count > maxApplications {
		return nil, fmt.Errorf("dmr: invalid application count")
	}
	apps := make([]Application, 0, int(count))
	offset := 16
	for i := uint32(0); i < count; i++ {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("dmr: missing application %d", i)
		}
		size := uint64(le.Uint32(data[offset:]))
		aligned := (size + 3) &^ uint64(3)
		if size < 36 || aligned > uint64(len(data)-offset) {
			return nil, fmt.Errorf("dmr: application outside APPS extent")
		}
		app, err := parseApplication(data[offset : offset+int(aligned)])
		if err != nil {
			return nil, fmt.Errorf("dmr: application %d: %w", i, err)
		}
		apps = append(apps, app)
		offset += int(aligned)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("dmr: trailing APPS bytes")
	}
	return apps, nil
}
