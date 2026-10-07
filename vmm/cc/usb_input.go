package cc

func (p *pc) keyEvent(name string, down bool) error {
	if p.uhci != nil {
		return p.uhci.devices[0].key(name, down)
	}
	return p.keyboard.key(name, down)
}
