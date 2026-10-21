package star

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/boot/darwin"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type arm64BootValue struct {
	boot    vmmapi.ARM64Boot
	handoff *darwin.ARM64Handoff
}

func (v *arm64BootValue) String() string        { return "<vmm.arm64_boot>" }
func (v *arm64BootValue) Type() string          { return "vmm_arm64_boot" }
func (v *arm64BootValue) Freeze()               {}
func (v *arm64BootValue) Truth() starlark.Bool  { return starlark.True }
func (v *arm64BootValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: vmm_arm64_boot") }
func (v *arm64BootValue) AttrNames() []string {
	return []string{"image", "address", "entry", "memory_base", "nvram", "read_only_address", "read_only_size"}
}

func darwinARM64BootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kernel, tree starlark.Value
	var memory uint64
	var base, virtual uint64
	command := "-v"
	entropyValue := starlark.Value(starlark.None)
	payloadValue := starlark.Value(starlark.None)
	nvramValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("darwin_arm64_boot", args, kwargs, "kernel", &kernel, "device_tree", &tree, "memory", &memory, "memory_base", &base, "virtual_base", &virtual, "command_line?", &command, "entropy?", &entropyValue, "payloads?", &payloadValue, "nvram?", &nvramValue); err != nil {
		return nil, err
	}
	k, ok := kernel.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("darwin_arm64_boot: expected kernel file")
	}
	t, ok := tree.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("darwin_arm64_boot: expected device tree file")
	}
	entropy := make([]byte, 256)
	if entropyValue == starlark.None {
		if _, err := rand.Read(entropy); err != nil {
			return nil, fmt.Errorf("darwin_arm64_boot: entropy: %w", err)
		}
	} else if seed, ok := entropyValue.(starlark.Bytes); ok && (len(seed) == 64 || len(seed) == 256) {
		entropy = []byte(seed)
	} else {
		return nil, fmt.Errorf("darwin_arm64_boot: entropy must be 64 or 256 bytes or None")
	}
	var payloads []darwin.ARM64Payload
	if payloadValue != starlark.None {
		dict, ok := payloadValue.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("darwin_arm64_boot: payloads must map memory-map names to files")
		}
		for _, pair := range dict.Items() {
			name, ok := starlark.AsString(pair[0])
			if !ok {
				return nil, fmt.Errorf("darwin_arm64_boot: payload name must be a string")
			}
			data, ok := pair[1].(storage.Reader)
			if !ok {
				return nil, fmt.Errorf("darwin_arm64_boot: payload must be a file")
			}
			payloads = append(payloads, darwin.ARM64Payload{Name: name, Data: data})
		}
	}
	var nvram []byte
	if nvramValue != starlark.None {
		var err error
		nvram, err = darwinARM64NVRAM(nvramValue)
		if err != nil {
			return nil, err
		}
	}
	h, err := darwin.PrepareARM64WithNVRAM(k, t, base, virtual, memory, command, entropy, nvram, payloads...)
	if err != nil {
		return nil, err
	}
	b := vmmapi.ARM64Boot{Image: h.Image, Address: h.Address, Entry: h.Entry, MemoryBase: base, MemorySize: memory}
	for _, p := range h.Payloads {
		b.Loads = append(b.Loads, vmmapi.ARM64Load{Image: p.Data, Address: p.Address})
	}
	b.X[0] = h.Arguments
	return &arm64BootValue{boot: b, handoff: h}, nil
}

// Unqualified names use Apple's common namespace. An explicit Apple common or
// system GUID followed by ':' selects the corresponding CHRP partition.
func darwinARM64NVRAM(value starlark.Value) ([]byte, error) {
	dict, ok := value.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("darwin_arm64_boot: nvram must map variable names to strings")
	}
	common, system := map[string]string{}, map[string]string{}
	for _, pair := range dict.Items() {
		name, nameOK := starlark.AsString(pair[0])
		value, valueOK := starlark.AsString(pair[1])
		if !nameOK || !valueOK {
			return nil, fmt.Errorf("darwin_arm64_boot: nvram names and values must be strings")
		}
		partition := common
		if nvramGUIDPrefix(name) {
			switch strings.ToLower(name[:36]) {
			case "7c436110-ab2a-4bbb-a880-fe41995c9f82":
				name = name[37:]
			case "40a0ddd2-77f8-4392-b4a3-1e7304206516":
				partition, name = system, name[37:]
			default:
				return nil, fmt.Errorf("darwin_arm64_boot: nvram supports only Apple common and system GUID prefixes")
			}
		}
		if _, exists := partition[name]; exists {
			return nil, fmt.Errorf("darwin_arm64_boot: duplicate nvram variable %q", name)
		}
		partition[name] = value
	}
	return darwin.ARM64NVRAM(8192, common, system)
}

func darwinNVRAMBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("darwin_nvram", args, kwargs, "values", &value); err != nil {
		return nil, err
	}
	bank, err := darwinARM64NVRAM(value)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(bank), nil
}

func nvramGUIDPrefix(name string) bool {
	if len(name) < 37 || name[36] != ':' {
		return false
	}
	for i := 0; i < 36; i++ {
		c := name[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (v *arm64BootValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "image":
		return starfile.NewReader("ARM64 firmware", v.boot.Image), nil
	case "address":
		return starlark.MakeUint64(v.boot.Address), nil
	case "entry":
		return starlark.MakeUint64(v.boot.Entry), nil
	case "memory_base":
		return starlark.MakeUint64(v.boot.MemoryBase), nil
	case "nvram":
		if v.handoff != nil {
			return starlark.Bytes(v.handoff.NVRAM), nil
		}
		return starlark.None, nil
	case "read_only_address":
		if v.handoff != nil {
			return starlark.MakeUint64(v.handoff.ReadOnlyAddress), nil
		}
		return starlark.MakeInt(0), nil
	case "read_only_size":
		if v.handoff != nil {
			return starlark.MakeUint64(v.handoff.ReadOnlySize), nil
		}
		return starlark.MakeInt(0), nil
	}
	return nil, nil
}
func arm64BootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image starlark.Value
	var address, base uint64
	entry := starlark.Value(starlark.None)
	var registers, system starlark.Value = starlark.None, starlark.None
	if err := starlark.UnpackArgs("arm64_boot", args, kwargs, "image", &image, "address", &address, "memory_base", &base, "entry?", &entry, "registers?", &registers, "system?", &system); err != nil {
		return nil, err
	}
	r, ok := image.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("arm64_boot: image must be a file")
	}
	b := vmmapi.ARM64Boot{Image: r, Address: address, Entry: address, MemoryBase: base, System: map[uint16]uint64{}}
	if entry != starlark.None {
		if err := starlark.AsInt(entry, &b.Entry); err != nil {
			return nil, err
		}
	}
	for _, d := range []struct {
		value  starlark.Value
		system bool
	}{{registers, false}, {system, true}} {
		if d.value == starlark.None {
			continue
		}
		dict, ok := d.value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("arm64_boot: registers and system must be dictionaries or None")
		}
		for _, pair := range dict.Items() {
			var key, value uint64
			if err := starlark.AsInt(pair[0], &key); err != nil {
				return nil, err
			}
			if err := starlark.AsInt(pair[1], &value); err != nil {
				return nil, err
			}
			if d.system {
				if key > 65535 {
					return nil, fmt.Errorf("arm64_boot: invalid system register")
				}
				b.System[uint16(key)] = value
			} else {
				if key >= 31 {
					return nil, fmt.Errorf("arm64_boot: expected register index 0..30")
				}
				b.X[key] = value
			}
		}
	}
	return &arm64BootValue{boot: b}, nil
}
