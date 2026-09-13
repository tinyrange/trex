package vmm

import "context"

// DisplayVM identifies a running VM in a browser workspace.
type DisplayVM struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Display DisplaySource `json:"-"`
}

// Workspace supplies displays and an optional recipe-owned VM factory.
// The native HTTP adapter owns routing; recipes own guest construction.
type Workspace interface {
	VMs() []DisplayVM
	CanCreate() bool
	Create(context.Context) (DisplayVM, error)
}
