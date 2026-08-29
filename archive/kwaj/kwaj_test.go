package kwaj

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func kwajTestFile(method uint16, decodedSize int, payload []byte) *starfile.Bytes {
	header := make([]byte, 18)
	copy(header[:8], kwajSignature)
	binary.LittleEndian.PutUint16(header[8:10], method)
	binary.LittleEndian.PutUint16(header[10:12], uint16(len(header)))
	binary.LittleEndian.PutUint16(header[12:14], 1)
	binary.LittleEndian.PutUint32(header[14:18], uint32(decodedSize))
	return &starfile.Bytes{Name: "fixture.kwj", Data: append(header, payload...)}
}

func kwajNamedTestFile(method uint16, name, extension string, payload []byte) *starfile.Bytes {
	header := make([]byte, 18, 18+len(name)+len(extension)+2+len(payload))
	copy(header[:8], kwajSignature)
	binary.LittleEndian.PutUint16(header[8:10], method)
	binary.LittleEndian.PutUint16(header[12:14], 1|8|16)
	binary.LittleEndian.PutUint32(header[14:18], uint32(len(payload)))
	header = append(header, name...)
	header = append(header, 0)
	header = append(header, extension...)
	header = append(header, 0)
	binary.LittleEndian.PutUint16(header[10:12], uint16(len(header)))
	return &starfile.Bytes{Name: "named.kwj", Data: append(header, payload...)}
}

func TestKWAJParsesOriginalNameMetadata(t *testing.T) {
	file := kwajNamedTestFile(0, "NOTEPAD", "EXE", []byte("program"))
	header, err := parseKWAJHeader(file, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if header.name != "NOTEPAD.EXE" || header.expected != 7 || header.method != 0 {
		t.Fatalf("header = name %q, size %d, method %d", header.name, header.expected, header.method)
	}
	decoded, err := decodeKWAJHeader(header, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.String() != `<file NOTEPAD.EXE size=7>` {
		t.Fatalf("decoded file = %s", decoded)
	}
}

type kwajTestBitWriter struct {
	data []byte
	bits int
}

func (w *kwajTestBitWriter) write(value uint32, count int) {
	for bit := count - 1; bit >= 0; bit-- {
		if w.bits%8 == 0 {
			w.data = append(w.data, 0)
		}
		w.data[len(w.data)-1] |= byte((value>>bit)&1) << (7 - (w.bits % 8))
		w.bits++
	}
}

func kwajFixedLiteralFixture(payload []byte) []byte {
	writer := &kwajTestBitWriter{}
	for index := 0; index < 6; index++ {
		writer.write(0, 4)
	}
	for _, value := range payload {
		writer.write(0, 4)
		writer.write(0, 5)
		writer.write(uint32(value), 8)
	}
	return writer.data
}

func TestKWAJMethodsDecodeOriginalFixtures(t *testing.T) {
	tests := []struct {
		name    string
		method  uint16
		payload []byte
		want    []byte
	}{
		{name: "stored", method: 0, payload: []byte("plain data"), want: []byte("plain data")},
		{name: "xor", method: 1, payload: []byte{0x97, 0x9a, 0x93, 0x93, 0x90}, want: []byte("hello")},
		{name: "lzss literals", method: 2, payload: []byte{0x1f, 'h', 'e', 'l', 'l', 'o'}, want: []byte("hello")},
		{name: "lzh literals", method: 3, payload: kwajFixedLiteralFixture([]byte("trex")), want: []byte("trex")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := kwajTestFile(test.method, len(test.want), test.payload)
			data, expected, method, offset, err := readKWAJHeader(file, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decompressKWAJ(data[offset:], method, expected, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("decoded = %q, want %q", got, test.want)
			}
		})
	}
}

func TestKWAJMSZIPCarriesDictionaryAcrossBlocks(t *testing.T) {
	first := bytes.Repeat([]byte("trex KWAJ dictionary fixture "), 2048)[:1<<15]
	second := append([]byte(nil), first...)
	copy(second[len(second)-len("installed image"):], "installed image")
	var payload []byte
	dictionary := []byte(nil)
	for _, block := range [][]byte{first, second} {
		var compressed bytes.Buffer
		compressed.WriteString("CK")
		var writer *flate.Writer
		var err error
		if dictionary == nil {
			writer, err = flate.NewWriter(&compressed, flate.BestCompression)
		} else {
			writer, err = flate.NewWriterDict(&compressed, flate.BestCompression, dictionary)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(block); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		length := make([]byte, 2)
		binary.LittleEndian.PutUint16(length, uint16(compressed.Len()))
		payload = append(payload, length...)
		payload = append(payload, compressed.Bytes()...)
		dictionary = block
		if len(dictionary) > 1<<15 {
			dictionary = dictionary[len(dictionary)-(1<<15):]
		}
	}
	payload = append(payload, 0, 0)
	want := append(append([]byte(nil), first...), second...)
	got, err := decompressKWAJMSZIP(payload, int64(len(want)), int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
	}
	got, err = decompressKWAJMSZIP(payload, -1, int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unsized decode produced %d bytes, want %d", len(got), len(want))
	}
}

func TestKWAJRejectsTruncationAndOversizedOutput(t *testing.T) {
	if _, _, _, _, err := readKWAJHeader(&starfile.Bytes{Name: "short", Data: []byte("KWAJ")}, 1024); err == nil {
		t.Fatal("truncated KWAJ header was accepted")
	}
	file := kwajTestFile(3, 4096, kwajFixedLiteralFixture([]byte("x")))
	if _, _, _, _, err := readKWAJHeader(file, 64); err == nil {
		t.Fatal("oversized decoded KWAJ stream was accepted")
	}
}
