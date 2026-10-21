// Package native supplies host repository ownership, separate from the portable engine.
package native

import (
	"github.com/tinyrange/trex/scs/repo"
	storagenative "github.com/tinyrange/trex/storage/native"
)

func Create(name string) (*repo.Repository, error) {
	f, e := storagenative.OpenStore(name, true)
	if e != nil {
		return nil, e
	}
	return repo.Create(f)
}
func CreateOptimized(name string) (*repo.Repository, error) {
	f, e := storagenative.OpenStore(name, true)
	if e != nil {
		return nil, e
	}
	return repo.CreateOptimized(f)
}
func Open(name string) (*repo.Repository, error) {
	f, e := storagenative.OpenStore(name, false)
	if e != nil {
		return nil, e
	}
	return repo.Open(f)
}
func OpenVerified(name string) (*repo.Repository, error) {
	f, e := storagenative.OpenStore(name, false)
	if e != nil {
		return nil, e
	}
	return repo.OpenVerified(f)
}
