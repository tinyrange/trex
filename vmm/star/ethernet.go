package star

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/vmm/ethernet"
	"go.starlark.net/starlark"
)

type switchValue struct{ switcher *ethernet.Switch }

// NewSwitchValue wraps an explicitly supplied private Ethernet domain for an
// embedding application's machine recipe. It does not attach a host network.
func NewSwitchValue(s *ethernet.Switch) starlark.Value { return &switchValue{switcher: s} }

func (*switchValue) String() string        { return "<vmm.switch>" }
func (*switchValue) Type() string          { return "vmm_switch" }
func (*switchValue) Freeze()               {}
func (*switchValue) Truth() starlark.Bool  { return true }
func (*switchValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable vmm switch") }
func switchBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var internet bool
	mac := "02:54:52:00:00:01"
	if err := starlark.UnpackArgs("switch", args, kwargs, "internet?", &internet, "mac?", &mac); err != nil {
		return nil, err
	}
	if internet {
		factory, ok := thread.Local(internetFactoryKey).(InternetFactory)
		if !ok {
			return nil, fmt.Errorf("internet requires trex -allow-internet")
		}
		guest, err := parseMAC(mac)
		if err != nil {
			return nil, err
		}
		lan, err := factory(guest)
		if err != nil {
			return nil, err
		}
		return NewSwitchValue(lan), nil
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
