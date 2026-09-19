package sevenzip

import (
	"bytes"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestBCJ2BranchesAndChunkBoundaries(t *testing.T) {
	// A single taken decision with initial probability 1/2 has code 7ffffc00.
	// Absolute target 12345678 at output offset 0 becomes displacement 12345673.
	for _, opcode := range []byte{0xe8, 0xe9, 0x85} {
		main := []byte{opcode}
		want := []byte{opcode, 0x73, 0x56, 0x34, 0x12}
		call, jump := []byte{}, []byte{}
		operand := []byte{0x12, 0x34, 0x56, 0x78}
		if opcode == 0xe8 {
			call = operand
		} else {
			jump = operand
		}
		if opcode == 0x85 {
			main = []byte{0x0f, opcode}
			want = []byte{0x0f, opcode, 0x72, 0x56, 0x34, 0x12}
		}
		for _, chunk := range []int{1, 2, 3, 4, 32} {
			streams := [][]byte{main, call, jump, {0, 0x7f, 0xff, 0xfc, 0}}
			r, err := bcj2TestReader(streams, uint64(len(want)))
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			buffer := make([]byte, chunk)
			for {
				var n int
				n, err = r.Read(buffer)
				got.Write(buffer[:n])
				if err == io.EOF {
					err = nil
					break
				}
				if err != nil {
					break
				}
			}
			if err != nil || !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("opcode %x chunk %d: %x, %v", opcode, chunk, got.Bytes(), err)
			}
		}
	}
}

func bcj2TestReader(streams [][]byte, size uint64) (*bcj2Reader, error) {
	var inputs []io.Reader
	var sizes []uint64
	for _, s := range streams {
		inputs = append(inputs, bytes.NewReader(s))
		sizes = append(sizes, uint64(len(s)))
	}
	return newBCJ2Reader(inputs, sizes, size)
}

func TestBCJ2UnconvertedMarkerAndInvalidStreams(t *testing.T) {
	for _, main := range [][]byte{nil, {0xe8}, {0x0f, 0x85}, []byte("ordinary text")} {
		r, err := bcj2TestReader([][]byte{main, nil, nil, {0, 0, 0, 0, 0}}, uint64(len(main)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, main) {
			t.Fatalf("%x %v", got, err)
		}
	}
	for _, streams := range [][][]byte{
		{{0xe8}, nil, nil, {0, 0x7f, 0xff, 0xfc, 0}}, // branch without operand
		{{0x90}, nil, nil, {1, 0, 0, 0, 0}},          // invalid prefix
		{{0x90}, nil, nil, {0, 0, 0, 0}},             // truncated range stream
		{{0x90}, nil, nil, {0, 0, 0, 0, 0, 0}},       // trailing data
		{{0x90}, nil, nil, {0, 0, 0, 0, 1}},          // unfinished range code
	} {
		r, err := bcj2TestReader(streams, 1)
		if err == nil {
			_, err = io.ReadAll(r)
		}
		if err == nil {
			t.Fatalf("accepted invalid streams %x", streams)
		}
	}
}

func TestSevenZipGraphWiring(t *testing.T) {
	// Terminal first, and deliberately shuffled packed order. This exercises
	// stream-index resolution independently of the archive's usual ordering.
	f := sevenZipFolder{
		coders:        []sevenZipCoder{{method: []byte{3, 3, 1, 0x1b}, inputs: 4, outputs: 1}, {method: []byte{0}, inputs: 1, outputs: 1}},
		bindPairs:     []sevenZipBindPair{{input: 0, output: 1}},
		packedIndices: []uint64{3, 2, 4, 1},
		unpackSizes:   []uint64{5, 1},
	}
	if err := validateSevenZipFolder(f); err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 0x7f, 0xff, 0xfc, 0, 0xe8, 0x12, 0x34, 0x56, 0x78}
	reader := &sevenZipFolderData{base: &starfile.Bytes{Data: data}, graph: f, packed: []sevenZipPackedStream{{0, 5}, {5, 0}, {5, 1}, {6, 4}}, unpackSize: 5}
	got, err := reader.all()
	if err != nil || !bytes.Equal(got, []byte{0xe8, 0x73, 0x56, 0x34, 0x12}) {
		t.Fatalf("%x %v", got, err)
	}
	f.bindPairs = append(f.bindPairs, sevenZipBindPair{input: 1, output: 1})
	if validateSevenZipFolder(f) == nil {
		t.Fatal("accepted reused output")
	}
	f = sevenZipFolder{coders: []sevenZipCoder{{method: []byte{0}, inputs: 1, outputs: 1}, {method: []byte{0}, inputs: 1, outputs: 1}}, unpackSizes: []uint64{1, 1}, bindPairs: []sevenZipBindPair{{input: 0, output: 0}}, packedIndices: []uint64{1}}
	if validateSevenZipFolder(f) == nil {
		t.Fatal("accepted disconnected cycle")
	}
}

func TestSevenZipRejectsBCJ2TrailerWithValidOutput(t *testing.T) {
	f := sevenZipFolder{
		coders:        []sevenZipCoder{{method: []byte{3, 3, 1, 0x1b}, inputs: 4, outputs: 1}},
		packedIndices: []uint64{0, 1, 2, 3}, unpackSizes: []uint64{1},
	}
	data := []byte{'a', 0, 0, 0, 0, 0, 0}
	r := &sevenZipFolderData{base: &starfile.Bytes{Data: data}, graph: f,
		packed: []sevenZipPackedStream{{0, 1}, {1, 0}, {1, 0}, {1, 6}}, unpackSize: 1}
	if _, err := r.all(); err == nil {
		t.Fatal("accepted extra RC byte after correct decoded output")
	}
}
