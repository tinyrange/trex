package windows

import (
	"encoding/binary"
	"fmt"
	"go.starlark.net/starlark"
)

// Packed user and virtualization-control nibbles occupy bits 16..19 and
// 20..23 of nk+0x34, respectively. Preserve the name maximum and other bits.
func (h *mutableHive) applyKeyFlags(value starlark.Value) error {
	record, ok := value.(*starlark.Dict)
	if !ok {
		return fmt.Errorf("expected key/key_parts and flag record")
	}
	for _, item := range record.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok || (name != "key" && name != "key_parts" && name != "user_flags" && name != "virtualization_flags") {
			return fmt.Errorf("unsupported key flag field %s", item[0])
		}
	}
	parts, _, err := registryPathFromDict(record)
	if err != nil {
		return err
	}
	mask, bits := uint32(0), uint32(0)
	for i, name := range []string{"user_flags", "virtualization_flags"} {
		raw, found, err := record.Get(starlark.String(name))
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		flag, ok := raw.(starlark.Int)
		if !ok {
			return fmt.Errorf("%s must be an integer in 0..15", name)
		}
		flags, ok := flag.Uint64()
		if !ok || flags > 15 {
			return fmt.Errorf("%s must be an integer in 0..15", name)
		}
		shift := uint(16 + i*4)
		mask |= 15 << shift
		bits |= uint32(flags) << shift
	}
	if mask == 0 {
		return fmt.Errorf("expected user_flags or virtualization_flags")
	}
	cell, err := h.lookupKeyParts(parts)
	if err != nil {
		return err
	}
	key, err := h.cellBody(cell)
	if err != nil {
		return err
	}
	if len(key) < 0x4c || string(key[:2]) != "nk" {
		return fmt.Errorf("invalid key cell")
	}
	packed := binary.LittleEndian.Uint32(key[0x34:0x38])
	binary.LittleEndian.PutUint32(key[0x34:0x38], packed&^mask|bits)
	// CmSetKeyFlags(class=2): disabling virtualization also clears the
	// persistent KEY_VIRTUAL_STORE bit; enabling does not manufacture it.
	if bits&(2<<20) != 0 {
		flags := binary.LittleEndian.Uint16(key[2:4])
		binary.LittleEndian.PutUint16(key[2:4], flags&^0x80)
	}
	return nil
}
