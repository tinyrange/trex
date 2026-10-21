package repo

import (
	"github.com/tinyrange/trex/storage/native"
)

func createTest(name string) (*Repository, error) {
	f, e := native.OpenStore(name, true)
	if e != nil {
		return nil, e
	}
	return Create(f)
}
func createTestOptimized(name string) (*Repository, error) {
	f, e := native.OpenStore(name, true)
	if e != nil {
		return nil, e
	}
	return CreateOptimized(f)
}
func openTest(name string) (*Repository, error) {
	f, e := native.OpenStore(name, false)
	if e != nil {
		return nil, e
	}
	return Open(f)
}
func openTestVerified(name string) (*Repository, error) {
	f, e := native.OpenStore(name, false)
	if e != nil {
		return nil, e
	}
	return OpenVerified(f)
}

func createTestMode(name string, optimized bool) (*Repository, error) {
	if optimized {
		return createTestOptimized(name)
	}
	return createTest(name)
}
