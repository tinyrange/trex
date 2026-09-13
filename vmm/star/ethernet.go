package star

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/vmm/ethernet"
	"go.starlark.net/starlark"
)

type switchValue struct{ switcher *ethernet.Switch }

func (*switchValue) String() string        { return "<vmm.switch>" }
func (*switchValue) Type() string          { return "vmm_switch" }
func (*switchValue) Freeze()               {}
func (*switchValue) Truth() starlark.Bool  { return true }
func (*switchValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable vmm switch") }
func switchBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("switch", args, kwargs); err != nil {
		return nil, err
	}
	return &switchValue{ethernet.NewSwitch()}, nil
}
func parseMAC(value string) ([6]byte, error) {
	var mac [6]byte
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return mac, fmt.Errorf("mac requires six colon-separated hexadecimal bytes")
	}
	for i, p := range parts {
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 1 {
			return mac, fmt.Errorf("invalid mac")
		}
		mac[i] = b[0]
	}
	if mac[0]&1 != 0 || mac == [6]byte{} {
		return mac, fmt.Errorf("mac must be nonzero unicast")
	}
	return mac, nil
}
