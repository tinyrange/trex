package aea

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func metadataFixture(records ...[]byte) []byte {
	b := []byte{'A', 'E', 'A', '1', 1, 0, 0, 7, 0, 0, 0, 0}
	for _, record := range records {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(record)+4))
		b = append(b, record...)
	}
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)-12))
	return b
}

func TestMetadataBinaryValuesAndBorrowing(t *testing.T) {
	if m, err := ReadMetadata(bytes.NewReader(metadataFixture())); err != nil || len(m.Values) != 0 {
		t.Fatalf("empty metadata: %v %v", m, err)
	}
	b := metadataFixture([]byte("url\x00https://example.invalid"), []byte("binary\x00\x00\xff\x01"), []byte("empty\x00"))
	m, err := ReadMetadata(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if m.Profile != 1 || m.ScryptStrength != 7 || !bytes.Equal(m.Values["binary"], []byte{0, 255, 1}) || len(m.Values) != 3 {
		t.Fatalf("metadata %+v", m)
	}
	b[16] = 'U'
	raw, err := io.ReadAll(io.NewSectionReader(m.AuthData, 0, m.AuthData.Size()))
	if err != nil || raw[4] != 'U' {
		t.Fatal("auth data not borrowed", err)
	}
}

func TestRejectMalformedMetadata(t *testing.T) {
	valid := metadataFixture([]byte("key\x00value"))
	badLength := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(badLength[12:], ^uint32(0))
	badAuth := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(badAuth[8:], 1<<20+1)
	for _, b := range [][]byte{
		valid[:11], valid[:len(valid)-1], badLength, badAuth,
		metadataFixture([]byte("key\x00x"), []byte("key\x00y")),
		metadataFixture([]byte("nonul")), metadataFixture([]byte{255, 0}),
		metadataFixture([]byte{0, 'x'}),
	} {
		if _, err := ReadMetadata(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted malformed metadata: %x", b)
		}
	}
}
