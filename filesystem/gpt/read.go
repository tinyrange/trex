package gpt

import (
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

// Partition retains the on-disk entry number and GUID bytes required by EFI
// hard-drive device paths. File is a bounded view, without copying disk bytes.
type Partition struct {
	Index                uint32
	TypeGUID, UniqueGUID [16]byte
	StartLBA, EndLBA     int64
	File                 storage.Reader
}

func Read(source storage.Reader) ([]Partition, error) {
	v, err := newGPTVolume(adapter.File(source))
	if err != nil {
		return nil, err
	}
	out := make([]Partition, len(v.partitions))
	for i, p := range v.partitions {
		out[i] = Partition{p.index, p.typeGUID, p.uniqueGUID, p.startLBA, p.endLBA, p.file}
	}
	return out, nil
}
