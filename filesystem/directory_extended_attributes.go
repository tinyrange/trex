package filesystem

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func extendedAttributesValue(eas []ExtendedAttribute) *starlark.List {
	values := make([]starlark.Value, 0, len(eas))
	for _, ea := range eas {
		d := starlark.NewDict(3)
		_ = d.SetKey(starlark.String("name"), starlark.String(ea.Name))
		_ = d.SetKey(starlark.String("flags"), starlark.MakeInt(int(ea.Flags)))
		_ = d.SetKey(starlark.String("value"), starlark.Bytes(ea.Value))
		values = append(values, d)
	}
	return starlark.NewList(values)
}

func (d *Directory) setExtendedAttributesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var values *starlark.List
	if err := starlark.UnpackArgs("set_extended_attributes", args, kwargs, "name", &name, "attributes", &values); err != nil {
		return nil, err
	}
	eas := make([]ExtendedAttribute, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		value, ok := values.Index(i).(*starlark.Dict)
		if !ok || value.Len() != 3 {
			return nil, fmt.Errorf("EA %d must contain name, flags and value", i)
		}
		fields := make([]starlark.Value, 3)
		for j, key := range []string{"name", "flags", "value"} {
			field, found, err := value.Get(starlark.String(key))
			if err != nil || !found {
				return nil, fmt.Errorf("EA %d missing %s", i, key)
			}
			fields[j] = field
		}
		eaName, ok := starlark.AsString(fields[0])
		if !ok {
			return nil, fmt.Errorf("EA %d name must be string", i)
		}
		flags, err := starlark.AsInt32(fields[1])
		if err != nil || flags < 0 || flags > 255 {
			return nil, fmt.Errorf("EA %d flags must be byte", i)
		}
		data, ok := fields[2].(starlark.Bytes)
		if !ok {
			return nil, fmt.Errorf("EA %d value must be bytes", i)
		}
		eas = append(eas, ExtendedAttribute{Name: eaName, Flags: byte(flags), Value: []byte(data)})
	}
	if err := d.SetExtendedAttributes(name, eas); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// SetExtendedAttributes replaces the complete EA set of an existing object.
// Validation precedes mutation. All hardlinks share the new EAs; link-local
// short names and every unrelated metadata field remain unchanged.
func (d *Directory) SetExtendedAttributes(name string, eas []ExtendedAttribute) error {
	name = storage.CleanPath(name)
	if _, ok := d.dirs[name]; !ok {
		if _, ok := d.files[name]; !ok {
			return fmt.Errorf("set_extended_attributes: path %q does not exist", name)
		}
	}
	if err := ValidateExtendedAttributes(eas); err != nil {
		return err
	}
	clone := func() []ExtendedAttribute {
		copied := make([]ExtendedAttribute, len(eas))
		for i, ea := range eas {
			copied[i] = ea
			copied[i].Value = append([]byte(nil), ea.Value...)
		}
		return copied
	}
	m := d.metadata[name]
	m.ExtendedAttributes = clone()
	d.SetMetadata(name, m)
	if m.HardLink != 0 && d.hardLinkRefs[m.HardLink] > 1 {
		for _, alias := range d.hardLinkNames[m.HardLink] {
			other := d.metadata[alias]
			if other.HardLink == m.HardLink {
				other.ExtendedAttributes = clone()
				d.metadata[alias] = other
			}
		}
	}
	return nil
}
