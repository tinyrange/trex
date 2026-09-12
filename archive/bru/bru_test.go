package bru

import (
	"bytes"
	"fmt"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func setNumber(b []byte, off, width int, n uint32) {
	copy(b[off:off+width], fmt.Sprintf("%*x", width, n))
}

func checksum(b []byte) {
	setNumber(b, 128, 8, 0)
	var sum uint32
	for _, value := range b {
		sum += uint32(int32(int8(value)))
	}
	setNumber(b, 128, 8, sum)
}

func fixture() (*starfile.Bytes, []byte) {
	contents := bytes.Repeat([]byte("payload!\x80\xff"), 240)
	data := make([]byte, 6*blockSize)
	for i, kind := range []uint32{archiveRecord, fileRecord, dataRecord, dataRecord, endRecord} {
		b := data[i*blockSize : (i+1)*blockSize]
		copy(b, "a")
		setNumber(b, 136, 8, uint32(i))
		setNumber(b, 144, 8, 0)
		setNumber(b, 152, 8, 123)
		setNumber(b, 176, 4, kind)
		if kind == fileRecord {
			for j := 0; j < 13; j++ {
				setNumber(b, 384+j*8, 8, 0)
			}
			setNumber(b, 384, 8, 0100644)
			setNumber(b, 440, 8, uint32(len(contents)))
		}
		if kind == dataRecord {
			setNumber(b, 144, 8, uint32(i-1))
			copy(b[256:], contents[(i-2)*payloadSize:])
		}
		checksum(b)
	}
	return &starfile.Bytes{Data: data}, contents
}

func TestReadMultiRecordFile(t *testing.T) {
	f, want := fixture()
	entries, err := Open(f, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("%v %v", entries, err)
	}
	got, err := starfile.ReadAll(entries[0].Data)
	if err != nil || !bytes.Equal(got, want) || entries[0].Path != "a" || entries[0].Mode != 0100644 {
		t.Fatalf("got %d bytes: %v", len(got), err)
	}
}

func TestRejectCorruption(t *testing.T) {
	for name, change := range map[string]func([]byte){
		"checksum":    func(b []byte) { b[2*blockSize+256] ^= 1 },
		"sequence":    func(b []byte) { r := b[2*blockSize : 3*blockSize]; setNumber(r, 144, 8, 7); checksum(r) },
		"name":        func(b []byte) { r := b[2*blockSize : 3*blockSize]; r[0] = 'b'; checksum(r) },
		"stamp":       func(b []byte) { r := b[2*blockSize : 3*blockSize]; setNumber(r, 152, 8, 1); checksum(r) },
		"size":        func(b []byte) { r := b[blockSize : 2*blockSize]; setNumber(r, 440, 8, 1<<30); checksum(r) },
		"compression": func(b []byte) { r := b[blockSize : 2*blockSize]; setNumber(r, 472, 8, 1); checksum(r) },
		"trailer":     func(b []byte) { b[len(b)-1] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := fixture()
			change(f.Data)
			if _, err := Open(f, 10); err == nil {
				t.Fatal("accepted corrupt input")
			}
		})
	}
	f, _ := fixture()
	for _, length := range []int{0, 2048, 4096, 8192, len(f.Data) - 1} {
		if _, err := Open(&starfile.Bytes{Data: f.Data[:length]}, 10); err == nil {
			t.Fatalf("accepted truncated length %d", length)
		}
	}
}

func TestChecksummedBufferPadding(t *testing.T) {
	f, _ := fixture()
	padding := f.Data[5*blockSize:]
	setNumber(padding, 180, 4, 0)
	copy(padding[1228:], []byte{16, 1, 252, 208, 16, 2, 60, 204})
	checksum(padding)
	if _, err := Open(f, 10); err != nil {
		t.Fatal(err)
	}
	padding[1228] ^= 1
	if _, err := Open(f, 10); err == nil {
		t.Fatal("accepted corrupted padding block")
	}
}
