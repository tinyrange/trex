package cc

import "fmt"

func (p *pc) cpuAddress(address uint64) uint64 {
	if p.a20Disabled {
		return address &^ (1 << 20)
	}
	return address
}
func (p *pc) updateA20() error {
	enabled := p.keyboard.output&2 != 0 || p.ports[0x92]&2 != 0
	if p.a20Disabled == !enabled {
		return nil
	}
	gate, ok := p.cpu.(interface{ SetA20(bool) error })
	if !ok {
		return fmt.Errorf("native accelerator does not support A20 gating")
	}
	if err := gate.SetA20(enabled); err != nil {
		return err
	}
	p.a20Disabled = !enabled
	return nil
}
