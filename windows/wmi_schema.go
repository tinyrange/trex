package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strconv"
	"strings"
)

type wmiClassLayout struct {
	definition *wmiDecodedClass
	properties []wmiDecodedProperty
	declaring  []string
	namespace  string
}

func (r *wmiRepositoryFile) classLayout(namespace, name string) (*wmiClassLayout, error) {
	if r.modern == nil {
		return nil, fmt.Errorf("wmi repository: class_layout currently requires a modern repository")
	}
	records := make(map[[2]uint32][]byte, len(r.records))
	for _, rec := range r.records {
		records[[2]uint32{rec.logicalPage, rec.id}] = rec.data
	}
	cache := map[string]*wmiClassLayout{}
	visiting := map[string]bool{}
	var resolve func(string, string) (*wmiClassLayout, error)
	resolve = func(ns, name string) (*wmiClassLayout, error) {
		ns = normalizeWMINamespace(ns, `ROOT\CIMV2`)
		identity := ns + "\x00" + strings.ToUpper(name)
		if got := cache[identity]; got != nil {
			return got, nil
		}
		if visiting[identity] {
			return nil, fmt.Errorf("wmi repository: class inheritance cycle")
		}
		visiting[identity] = true
		defer delete(visiting, identity)
		var data []byte
		foundNS := ""
		for _, candidate := range []string{ns, "__SYSTEMCLASS"} {
			prefix := "NS_" + wmiUpperUTF16SHA256(candidate) + `\CD_` + wmiUpperUTF16SHA256(name) + "."
			for _, page := range r.pages {
				for _, key := range page.keys {
					if strings.HasPrefix(key, prefix) {
						if data != nil {
							return nil, fmt.Errorf("wmi repository: ambiguous class %s", identity)
						}
						parts := strings.Split(key, ".")
						p, _ := strconv.ParseUint(parts[1], 10, 32)
						id, _ := strconv.ParseUint(parts[2], 10, 32)
						data = records[[2]uint32{uint32(p), uint32(id)}]
						foundNS = candidate
					}
				}
			}
			if data != nil {
				break
			}
		}
		if data == nil {
			return nil, fmt.Errorf("wmi repository: class %s not found in %s or intrinsic namespace", name, ns)
		}
		decoded, err := decodeWMIClassRecord(data)
		if err != nil {
			return nil, fmt.Errorf("wmi repository: class %s: %w", name, err)
		}
		if !strings.EqualFold(decoded.class.Name, name) {
			return nil, fmt.Errorf("wmi repository: class name/hash mismatch")
		}
		decoded.class.Namespace = foundNS
		result := &wmiClassLayout{definition: decoded, namespace: foundNS}
		if decoded.class.Super != "" {
			parent, err := resolve(foundNS, decoded.class.Super)
			if err != nil {
				return nil, err
			}
			result.properties = append(result.properties, parent.properties...)
			result.declaring = append(result.declaring, parent.declaring...)
		}
		for _, property := range decoded.properties {
			if int(property.index) > len(result.properties) {
				return nil, fmt.Errorf("wmi repository: noncontiguous property index %s.%s=%d", name, property.feature.Name, property.index)
			}
			if int(property.index) == len(result.properties) {
				result.properties = append(result.properties, property)
				result.declaring = append(result.declaring, decoded.class.Name)
			} else {
				if !strings.EqualFold(result.properties[property.index].feature.Name, property.feature.Name) {
					return nil, fmt.Errorf("wmi repository: inherited property index mismatch")
				}
				if property.code&0x4000 != 0 {
					inherited := result.properties[property.index].feature
					property.feature.Type = inherited.Type
					qualifiers := append([]mofQualifier(nil), inherited.Qualifiers...)
					for _, q := range property.feature.Qualifiers {
						replaced := false
						for j := range qualifiers {
							if strings.EqualFold(qualifiers[j].Name, q.Name) {
								qualifiers[j] = q
								replaced = true
								break
							}
						}
						if !replaced {
							qualifiers = append(qualifiers, q)
						}
					}
					property.feature.Qualifiers = qualifiers
					property.feature.Value = inherited.Value
				}
				result.properties[property.index] = property
			}
		}
		nullSize := (len(result.properties)*2 + 7) / 8
		if len(decoded.defaults) < nullSize {
			return nil, fmt.Errorf("wmi repository: truncated class default states")
		}
		expectedOffset := uint32(0)
		for i := range result.properties {
			property := &result.properties[i]
			_, size, err := wmiDecodeType(property.code)
			if err != nil {
				return nil, err
			}
			if property.index != uint32(i) || property.offset != expectedOffset {
				return nil, fmt.Errorf("wmi repository: unsupported property layout %s.%s index=%d offset=%d expected=%d", name, property.feature.Name, property.index, property.offset, expectedOffset)
			}
			expectedOffset += uint32(size)
			if uint64(nullSize)+uint64(expectedOffset) > uint64(len(decoded.defaults)) {
				return nil, fmt.Errorf("wmi repository: truncated class defaults")
			}
			state := (decoded.defaults[i/4] >> uint(i%4*2)) & 3
			if state&2 != 0 {
				continue
			}
			property.feature.Value = nil
			if state&1 == 0 {
				v, err := wmiDecodeValue(decoded.defaults[nullSize+int(property.offset):], decoded.heap, property.code)
				if err != nil {
					return nil, err
				}
				property.feature.Value = &v
			}
		}
		if nullSize+int(expectedOffset) != len(decoded.defaults) {
			return nil, fmt.Errorf("wmi repository: unexpected class default padding")
		}
		// Local features retain their actual layout ordering; inherited properties
		// and their ownership are available separately to the instance encoder.
		for _, p := range decoded.properties {
			if p.code&0x4000 == 0 {
				decoded.class.Features = append(decoded.class.Features, result.properties[p.index].feature)
			}
		}
		cache[identity] = result
		return result, nil
	}
	return resolve(namespace, name)
}
func (r *wmiRepositoryFile) classLayoutBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace, name string
	if err := starlark.UnpackArgs("class_layout", args, kwargs, "namespace", &namespace, "name", &name); err != nil {
		return nil, err
	}
	layout, err := r.classLayout(namespace, name)
	if err != nil {
		return nil, err
	}
	props := make([]starlark.Value, len(layout.properties))
	for i, p := range layout.properties {
		props[i] = starfile.NewRecord(starlark.StringDict{"property": mofFeatureValue(p.feature), "index": starlark.MakeUint(uint(p.index)), "offset": starlark.MakeUint(uint(p.offset)), "declaring_class": starlark.String(layout.declaring[i])})
	}
	return starfile.NewRecord(starlark.StringDict{"class": mofClassValue(layout.definition.class), "revision": starlark.MakeUint64(layout.definition.revision), "properties": starlark.NewList(props)}), nil
}
