package vmsbackup

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func fileMetadata(size int64) []byte {
	rms := make([]byte, 32)
	eof := uint32(size/512 + 1)
	binary.LittleEndian.PutUint16(rms[8:], uint16(eof>>16))
	binary.LittleEndian.PutUint16(rms[10:], uint16(eof))
	binary.LittleEndian.PutUint16(rms[12:], uint16(size%512))
	data := []byte{1, 1}
	for _, a := range []Attribute{{42, []byte("[TEST]FILE.DAT;1")}, {52, rms}, {999, []byte{7}}} {
		data = binary.LittleEndian.AppendUint16(data, uint16(len(a.Data)))
		data = binary.LittleEndian.AppendUint16(data, a.Kind)
		data = append(data, a.Data...)
	}
	return data
}

func fileRecord(size int64) Record {
	return Record{Kind: 3, Flags: 2, Data: bytes.NewReader(fileMetadata(size))}
}

func TestFiles(t *testing.T) {
	x, y := bytes.Repeat([]byte{1}, 512), bytes.Repeat([]byte{2}, 512)
	// Real streams can contain a zero-length data record before the first
	// payload, retaining VBN1 rather than advancing it.
	blocks := []Block{{Records: []Record{fileRecord(600), {Kind: 4, Address: 1, Data: bytes.NewReader(nil)}, {Kind: 4, Address: 1, Data: bytes.NewReader(x)}}},
		{Parity: true}, {Records: []Record{{Kind: 0}, {Kind: 4, Address: 2, Data: bytes.NewReader(y)}, fileRecord(1536), fileRecord(0)}}}
	files, err := Files(blocks, 3, 10)
	if err != nil || len(files) != 3 {
		t.Fatal(files, err)
	}
	f := files[0]
	if f.Size != 600 || f.StoredSize != 1024 || f.MissingContents || f.Flags != 2 || f.Attributes[2].Kind != 999 {
		t.Fatal(f)
	}
	data, err := io.ReadAll(io.NewSectionReader(f.Data, 0, f.Data.Size()))
	if err != nil || !bytes.Equal(data, append(bytes.Clone(x), y[:88]...)) {
		t.Fatal("logical payload", err)
	}
	buf := make([]byte, 100)
	n, err := f.Data.ReadAt(buf, 500)
	if n != 100 || err != nil || !bytes.Equal(buf, data[500:600]) {
		t.Fatal("cross extent", n, err)
	}
	n, err = f.Data.ReadAt(buf, 550)
	if n != 50 || err != io.EOF {
		t.Fatal("slack exposed", n, err)
	}
	x[0] = 3
	_, _ = f.Data.ReadAt(buf[:1], 0)
	if buf[0] != 3 {
		t.Fatal("payload was copied")
	}
	if _, err := f.Data.ReadAt(buf, -1); err == nil {
		t.Fatal("negative offset")
	}
	if !files[1].MissingContents || files[1].Data != nil || files[1].Size != 1536 || files[1].StoredSize != 0 {
		t.Fatal("missing contents fabricated", files[1])
	}
	if files[2].MissingContents || files[2].Data == nil || files[2].Data.Size() != 0 {
		t.Fatal("empty file is not missing", files[2])
	}
	if _, err := Files(blocks, 2, 10); err == nil {
		t.Fatal("file limit")
	}
	if _, err := Files(blocks, 3, 2); err == nil {
		t.Fatal("attribute limit")
	}
}

func TestFilesRejectInvalidChains(t *testing.T) {
	d := Record{Kind: 4, Address: 1, Data: bytes.NewReader(make([]byte, 512))}
	for name, records := range map[string][]Record{
		"orphan":             {d},
		"partial":            {fileRecord(600), d},
		"repeated":           {fileRecord(600), d, d},
		"gap":                {fileRecord(600), {Kind: 4, Address: 2, Data: d.Data}},
		"unknown":            {fileRecord(0), {Kind: 99}},
		"missing attributes": {{Kind: 3, Data: bytes.NewReader([]byte{1, 1})}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Files([]Block{{Records: records}}, 10, 10); err == nil {
				t.Fatal("accepted invalid chain")
			}
		})
	}
}

func TestFilesInvalidMetadata(t *testing.T) {
	const rmsStart = 2 + 4 + len("[TEST]FILE.DAT;1") + 4
	for name, mutate := range map[string]func([]byte) []byte{
		"free byte":           func(b []byte) []byte { binary.LittleEndian.PutUint16(b[rmsStart+12:], 513); return b },
		"zero EOF with bytes": func(b []byte) []byte { clear(b[rmsStart+8 : rmsStart+12]); return b },
		"duplicate name":      func(b []byte) []byte { return append(b, 1, 0, 42, 0, 'X') },
		"duplicate RMS":       func(b []byte) []byte { b = append(b, 32, 0, 52, 0); return append(b, make([]byte, 32)...) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(fileMetadata(600))
			if _, err := Files([]Block{{Records: []Record{{Kind: 3, Data: bytes.NewReader(raw)}}}}, 10, 10); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
}

func TestFilesEndOfBlockEOF(t *testing.T) {
	const rmsStart = 2 + 4 + len("[TEST]FILE.DAT;1") + 4
	raw := fileMetadata(512)
	binary.LittleEndian.PutUint16(raw[rmsStart+10:], 1)
	binary.LittleEndian.PutUint16(raw[rmsStart+12:], 512)
	files, err := Files([]Block{{Records: []Record{{Kind: 3, Data: bytes.NewReader(raw)}}}}, 1, 10)
	if err != nil || len(files) != 1 || files[0].Size != 512 || !files[0].MissingContents {
		t.Fatal(files, err)
	}
}
