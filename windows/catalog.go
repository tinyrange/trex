package windows

import (
	"encoding/asn1"
	"fmt"

	"go.starlark.net/starlark"
)

var pkcs7SignedDataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

type derValue struct {
	class       int
	tag         int
	constructed bool
	content     []byte
	raw         []byte
	children    []derValue
}

func catalogMembersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("catalog_members", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("catalog_members: %w", err)
	}
	members, err := parseCatalogMembers(data)
	if err != nil {
		return nil, fmt.Errorf("catalog_members: %w", err)
	}
	values := make([]starlark.Value, len(members))
	for index, member := range members {
		values[index] = starlark.Bytes(member)
	}
	return starlark.NewList(values), nil
}

func parseCatalogMembers(data []byte) ([][]byte, error) {
	values, err := parseDERValues(data)
	if err != nil {
		return nil, err
	}
	if len(values) != 1 || values[0].class != 0 || values[0].tag != 16 {
		return nil, fmt.Errorf("expected one PKCS#7 ContentInfo sequence")
	}
	contentInfo := values[0]
	if len(contentInfo.children) != 2 || !derOIDEqual(contentInfo.children[0], pkcs7SignedDataOID) {
		return nil, fmt.Errorf("expected PKCS#7 SignedData")
	}
	signedWrapper := contentInfo.children[1]
	if signedWrapper.class != 2 || signedWrapper.tag != 0 || len(signedWrapper.children) != 1 {
		return nil, fmt.Errorf("invalid SignedData wrapper")
	}
	signedData := signedWrapper.children[0]
	if signedData.class != 0 || signedData.tag != 16 || len(signedData.children) < 3 {
		return nil, fmt.Errorf("invalid SignedData sequence")
	}
	encapsulated := signedData.children[2]
	if encapsulated.class != 0 || encapsulated.tag != 16 || len(encapsulated.children) < 2 {
		return nil, fmt.Errorf("SignedData has no encapsulated catalog content")
	}
	payloadWrapper := encapsulated.children[1]
	if payloadWrapper.class != 2 || payloadWrapper.tag != 0 || len(payloadWrapper.children) != 1 {
		return nil, fmt.Errorf("invalid encapsulated catalog wrapper")
	}
	payload := payloadWrapper.children[0]
	var catalogValues []derValue
	if payload.class == 0 && payload.tag == 4 && !payload.constructed {
		catalogValues, err = parseDERValues(payload.content)
		if err != nil {
			return nil, fmt.Errorf("invalid embedded catalog content: %w", err)
		}
	} else {
		catalogValues = []derValue{payload}
	}
	members := make([][]byte, 0)
	for _, value := range catalogValues {
		collectCatalogDigests(value, &members)
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("catalog contains no SHA-1 members")
	}
	return members, nil
}

func collectCatalogDigests(value derValue, members *[][]byte) {
	if value.class == 0 && value.tag == 4 && !value.constructed && len(value.content) == 20 {
		*members = append(*members, append([]byte(nil), value.content...))
	}
	for _, child := range value.children {
		collectCatalogDigests(child, members)
	}
}

func derOIDEqual(value derValue, expected asn1.ObjectIdentifier) bool {
	if value.class != 0 || value.tag != 6 {
		return false
	}
	var actual asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(value.raw, &actual)
	return err == nil && len(rest) == 0 && actual.Equal(expected)
}

func parseDERValues(data []byte) ([]derValue, error) {
	values := make([]derValue, 0)
	for offset := 0; offset < len(data); {
		value, size, err := parseDERValue(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("DER at %#x: %w", offset, err)
		}
		values = append(values, value)
		offset += size
	}
	return values, nil
}

func parseDERValue(data []byte) (derValue, int, error) {
	if len(data) < 2 {
		return derValue{}, 0, fmt.Errorf("truncated element")
	}
	identifier := data[0]
	class := int(identifier >> 6)
	constructed := identifier&0x20 != 0
	tag := int(identifier & 0x1f)
	cursor := 1
	if tag == 0x1f {
		tag = 0
		for {
			if cursor >= len(data) || cursor > 6 {
				return derValue{}, 0, fmt.Errorf("invalid high tag")
			}
			part := data[cursor]
			cursor++
			tag = tag<<7 | int(part&0x7f)
			if part&0x80 == 0 {
				break
			}
		}
	}
	if cursor >= len(data) {
		return derValue{}, 0, fmt.Errorf("missing length")
	}
	length := int(data[cursor])
	cursor++
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || cursor+count > len(data) {
			return derValue{}, 0, fmt.Errorf("invalid length")
		}
		length = 0
		for _, part := range data[cursor : cursor+count] {
			length = length<<8 | int(part)
		}
		cursor += count
	}
	if length < 0 || cursor+length > len(data) {
		return derValue{}, 0, fmt.Errorf("element exceeds input")
	}
	size := cursor + length
	value := derValue{
		class:       class,
		tag:         tag,
		constructed: constructed,
		content:     data[cursor:size],
		raw:         data[:size],
	}
	if constructed {
		children, err := parseDERValues(value.content)
		if err != nil {
			return derValue{}, 0, err
		}
		value.children = children
	}
	return value, size, nil
}
