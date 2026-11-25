//go:build !linux || !amd64

package cc

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
)

func prepareRAM(storage.Reader, bool) (preparedRAM, error) {
	return nil, fmt.Errorf("cc.prepare_ram requires Linux x86-64")
}

func sampleRAM([]byte) ([]byte, error) {
	return nil, fmt.Errorf("cc.sample_physical requires Linux x86-64")
}

func privateResidentRAM([]byte) (int, error) {
	return 0, fmt.Errorf("private RAM accounting requires Linux x86-64")
}
