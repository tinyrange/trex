package sevenzip

import (
	"fmt"
	"io"
	"math"
)

type sevenZipPackedStream struct{ offset, size int64 }

// Supported coders have one output. Inputs are wired by their global stream
// indices, not by coder order (BCJ2 archives commonly put the terminal last).
func validateSevenZipFolder(f sevenZipFolder) error {
	if len(f.coders) == 0 || len(f.coders) > 64 || len(f.unpackSizes) != len(f.coders) {
		return fmt.Errorf("7z: invalid coder/output count")
	}
	inputs := 0
	starts := make([]int, len(f.coders))
	for i, c := range f.coders {
		want := uint64(1)
		switch sevenZipMethodName(c.method) {
		case "copy":
			if len(c.properties) != 0 {
				return fmt.Errorf("7z: copy coder has properties")
			}
		case "lzma":
			if len(c.properties) != 5 {
				return fmt.Errorf("7z: invalid LZMA properties")
			}
		case "lzma2":
			if len(c.properties) != 1 || c.properties[0] > 40 {
				return fmt.Errorf("7z: invalid LZMA2 properties")
			}
		case "bcj":
			if len(c.properties) != 0 && len(c.properties) != 4 {
				return fmt.Errorf("7z: invalid BCJ properties")
			}
		case "bcj2":
			want = 4
			if len(c.properties) != 0 {
				return fmt.Errorf("7z: BCJ2 coder has properties")
			}
		default:
			return fmt.Errorf("7z: unsupported coder method %x", c.method)
		}
		if c.inputs != want || c.outputs != 1 || f.unpackSizes[i] > math.MaxInt64 {
			return fmt.Errorf("7z: invalid streams or size for coder %x", c.method)
		}
		starts[i] = inputs
		inputs += int(want)
	}
	owners := make([]int, inputs)
	for i := range owners {
		owners[i] = -1
	}
	bound := make([]bool, len(f.coders))
	for _, pair := range f.bindPairs {
		if pair.input >= uint64(inputs) || pair.output >= uint64(len(bound)) || owners[pair.input] != -1 || bound[pair.output] {
			return fmt.Errorf("7z: duplicate or invalid bind pair")
		}
		owners[pair.input] = int(pair.output)
		bound[pair.output] = true
	}
	for _, input := range f.packedIndices {
		if input >= uint64(inputs) || owners[input] != -1 {
			return fmt.Errorf("7z: duplicate or invalid packed stream")
		}
		owners[input] = -2
	}
	for _, owner := range owners {
		if owner == -1 {
			return fmt.Errorf("7z: unconnected input")
		}
	}
	terminal := -1
	for i, used := range bound {
		if !used {
			if terminal != -1 {
				return fmt.Errorf("7z: multiple terminal outputs")
			}
			terminal = i
		}
	}
	if terminal == -1 {
		return fmt.Errorf("7z: no terminal output")
	}
	state := make([]byte, len(f.coders))
	var visit func(int) error
	visit = func(i int) error {
		if state[i] == 1 {
			return fmt.Errorf("7z: coder graph cycle")
		}
		if state[i] == 2 {
			return nil
		}
		state[i] = 1
		for j := starts[i]; j < starts[i]+int(f.coders[i].inputs); j++ {
			if owners[j] >= 0 {
				if err := visit(owners[j]); err != nil {
					return err
				}
			}
		}
		state[i] = 2
		return nil
	}
	if err := visit(terminal); err != nil {
		return err
	}
	for _, s := range state {
		if s != 2 {
			return fmt.Errorf("7z: disconnected coder graph")
		}
	}
	return nil
}

func (f *sevenZipFolderData) graphReader() (io.Reader, error) {
	inputs := make(map[uint64]io.Reader)
	sizes := make(map[uint64]uint64)
	for i, index := range f.graph.packedIndices {
		p := f.packed[i]
		inputs[index] = io.NewSectionReader(f.base, p.offset, p.size)
		sizes[index] = uint64(p.size)
	}
	bound := make(map[uint64]int)
	used := make(map[int]bool)
	for _, pair := range f.graph.bindPairs {
		bound[pair.input] = int(pair.output)
		used[int(pair.output)] = true
	}
	starts := make([]uint64, len(f.graph.coders))
	var next uint64
	for i, c := range f.graph.coders {
		starts[i] = next
		next += c.inputs
	}
	var build func(int) (io.Reader, error)
	build = func(i int) (io.Reader, error) {
		c := f.graph.coders[i]
		readers := make([]io.Reader, c.inputs)
		lengths := make([]uint64, c.inputs)
		for j := range readers {
			index := starts[i] + uint64(j)
			if from, ok := bound[index]; ok {
				r, err := build(from)
				if err != nil {
					return nil, err
				}
				readers[j], lengths[j] = r, f.graph.unpackSizes[from]
			} else {
				readers[j], lengths[j] = inputs[index], sizes[index]
			}
		}
		size := f.graph.unpackSizes[i]
		switch sevenZipMethodName(c.method) {
		case "copy":
			if lengths[0] != size {
				return nil, fmt.Errorf("7z: copy stream size mismatch")
			}
			return readers[0], nil
		case "lzma":
			return newLZMAReader(readers[0], c.properties, size, f.maximumDictionary)
		case "lzma2":
			return newLZMA2Reader(readers[0], c.properties, size, f.maximumDictionary)
		case "bcj":
			if lengths[0] != size {
				return nil, fmt.Errorf("7z: BCJ stream size mismatch")
			}
			return newBCJReader(readers[0], size, c.properties)
		case "bcj2":
			return newBCJ2Reader(readers, lengths, size)
		}
		return nil, fmt.Errorf("7z: unsupported coder")
	}
	for i := range f.graph.coders {
		if !used[i] {
			return build(i)
		}
	}
	return nil, fmt.Errorf("7z: no terminal output")
}
