package cc

func (p *pc) keyEvent(name string, down bool) error {
	if p.uhci != nil && p.uhci.devices[0].configuration != 0 {
		return p.uhci.devices[0].key(name, down)
	}
	return p.keyboard.key(name, down)
}
