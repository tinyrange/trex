package lzms

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

func testContainer(payload []byte, outputSize, chunkSize uint64) []byte {
	header := make([]byte, compressionAPIHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], CompressionAPIMagic)
	binary.LittleEndian.PutUint16(header[4:6], compressionAPIHeaderSize)
	header[7] = compressionAPIAlgorithm
	binary.LittleEndian.PutUint64(header[8:16], outputSize)
	binary.LittleEndian.PutUint32(header[16:20], uint32(chunkSize))
	header[6] = containerHeaderCRC(header)
	container := append([]byte(nil), header...)
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(payload)))
	container = append(container, size...)
	return append(container, payload...)
}

func TestDecompressContainerVerbatimChunks(t *testing.T) {
	first := testContainer([]byte("hello"), 11, 5)
	secondSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(secondSize, 5)
	first = append(first, secondSize...)
	first = append(first, " worl"...)
	lastSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(lastSize, 1)
	first = append(first, lastSize...)
	first = append(first, 'd')

	got, err := DecompressContainer(first, 11)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello world")) {
		t.Fatalf("output = %q", got)
	}
}

func TestDecompressContainerRejectsMalformedFraming(t *testing.T) {
	valid := testContainer([]byte("hello"), 5, 5)
	tests := []struct {
		name  string
		data  []byte
		limit uint64
	}{
		{name: "short header", data: valid[:23], limit: 5},
		{name: "output limit", data: valid, limit: 4},
		{name: "truncated chunk", data: valid[:len(valid)-1], limit: 5},
		{name: "trailing data", data: append(append([]byte(nil), valid...), 0), limit: 5},
	}
	badCRC := append([]byte(nil), valid...)
	badCRC[6] ^= 1
	tests = append(tests, struct {
		name  string
		data  []byte
		limit uint64
	}{name: "header CRC", data: badCRC, limit: 5})
	oversized := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(oversized[24:28], 6)
	tests = append(tests, struct {
		name  string
		data  []byte
		limit uint64
	}{name: "oversized chunk", data: oversized, limit: 5})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecompressContainer(test.data, test.limit); err == nil {
				t.Fatal("malformed container was accepted")
			}
		})
	}
}

func TestDecompressContainerRejectsUnsupportedHeaderValues(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(data []byte) { data[7] = 4 },
		func(data []byte) { binary.LittleEndian.PutUint32(data[16:20], 0) },
		func(data []byte) { binary.LittleEndian.PutUint32(data[20:24], 1) },
	} {
		data := testContainer([]byte("x"), 1, 1)
		mutate(data)
		data[6] = containerHeaderCRC(data[:compressionAPIHeaderSize])
		if _, err := DecompressContainer(data, 1); err == nil {
			t.Fatal("unsupported header value was accepted")
		}
	}
}

func TestDecompressContainerMicrosoftFixtures(t *testing.T) {
	for _, test := range []struct {
		name, encoded, hash string
		size                int
	}{
		{
			name: "english", size: 1600,
			encoded: "ClHlwBgAhAVABgAAAAAAAEAGAAAAAAAAkgAAAAQARfdrtfrZUm9WA3h6mDEAAOo527nksWWgsh4yuTA9q9eV9CaGsbpsq4gwZnNhcmIVCJ1ZGJmmLI/tzC0Nr8oBuXtDqpDmzqxTcm91cWlVkVuZnqVTpZmBVDtpdxZRpZTXZh2FQYG4nL2RgeTphbFZPnQgcmV2byBzcG11aiB4b2YgbndvcmIga2NpdXEgZWhU",
			hash:    "c499ced01eba23df9a46e68de3db441945f1e46d3ceb97270aeb471f1c34753c",
		},
		{
			name: "pattern", size: 8192,
			encoded: "ClHlwBgAWQUAIAAAAAAAAAAgAAAAAAAAEgAAADgT0L8AANB0gX6+uv7K776t3g==",
			hash:    "d0691fda8844318e6b51e6099ffef9ffe0f88a96a5971d28e2c5c4e39224c046",
		},
		{
			name: "sequential", size: 1024,
			encoded: "ClHlwBgAKwUABAAAAAAAAAAEAAAAAAAADgAAAEJr0P8AAKCK2VoaAgEA",
			hash:    "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			container, err := base64.StdEncoding.DecodeString(test.encoded)
			if err != nil {
				t.Fatal(err)
			}
			output, err := DecompressContainer(container, uint64(test.size))
			if err != nil {
				t.Fatal(err)
			}
			if len(output) != test.size || fmt.Sprintf("%x", sha256.Sum256(output)) != test.hash {
				t.Fatalf("output size/hash = %d/%x", len(output), sha256.Sum256(output))
			}
		})
	}
}
