package windows

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// A SystemCertificates Blob is a sequence of (property, encoding, length,
// value) records. Properties are preserved; their policy is NOT evaluated.
func parseSerializedCertificate(data []byte) (*x509.Certificate, map[uint32][]byte, error) {
	if len(data) > 1<<20 {
		return nil, nil, fmt.Errorf("certificate blob exceeds 1 MiB")
	}
	properties := map[uint32][]byte{}
	for len(data) > 0 {
		if len(data) < 12 || len(properties) >= 256 {
			return nil, nil, fmt.Errorf("truncated or excessive certificate properties")
		}
		id := binary.LittleEndian.Uint32(data)
		encoding := binary.LittleEndian.Uint32(data[4:])
		size := uint64(binary.LittleEndian.Uint32(data[8:]))
		data = data[12:]
		if encoding != 1 || size > uint64(len(data)) {
			return nil, nil, fmt.Errorf("invalid certificate property encoding or length")
		}
		if _, ok := properties[id]; ok {
			return nil, nil, fmt.Errorf("duplicate certificate property %d", id)
		}
		properties[id] = bytes.Clone(data[:int(size)])
		data = data[int(size):]
	}
	der, ok := properties[32]
	if !ok {
		return nil, nil, fmt.Errorf("certificate property 32 is missing")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if expected, ok := properties[3]; ok {
		hash := sha1.Sum(der)
		if !bytes.Equal(expected, hash[:]) {
			return nil, nil, fmt.Errorf("certificate SHA-1 property mismatch")
		}
	}
	return cert, properties, nil
}

func serializedCertificateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("serialized_certificate", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 1<<20)
	if err != nil {
		return nil, err
	}
	cert, properties, err := parseSerializedCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("serialized_certificate: %w", err)
	}
	props := starlark.NewDict(len(properties))
	for id, data := range properties {
		if err := props.SetKey(starlark.MakeUint64(uint64(id)), starlark.Bytes(data)); err != nil {
			return nil, err
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"certificate": certificateStarlarkValue(cert, sha1.Sum(cert.Raw)),
		"properties":  props,
	}), nil
}
