package lzms

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestPrefixPreservesFullSizeCodingAndRestoration(t *testing.T) {
	for _, encoded := range []string{
		"ClHlwBgAhAVABgAAAAAAAEAGAAAAAAAAkgAAAAQARfdrtfrZUm9WA3h6mDEAAOo527nksWWgsh4yuTA9q9eV9CaGsbpsq4gwZnNhcmIVCJ1ZGJmmLI/tzC0Nr8oBuXtDqpDmzqxTcm91cWlVkVuZnqVTpZmBVDtpdxZRpZTXZh2FQYG4nL2RgeTphbFZPnQgcmV2byBzcG11aiB4b2YgbndvcmIga2NpdXEgZWhU",
		"ClHlwBgAWQUAIAAAAAAAAAAgAAAAAAAAEgAAADgT0L8AANB0gX6+uv7K776t3g==",
		"ClHlwBgAKwUABAAAAAAAAAAEAAAAAAAADgAAAEJr0P8AAKCK2VoaAgEA",
	} {
		container, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		full, err := DecompressContainer(container, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		raw := container[28:]
		for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 511, 512, 513, len(full) - 17, len(full) - 16, len(full) - 15, len(full) - 1, len(full)} {
			if size < 0 || size > len(full) {
				continue
			}
			prefix, err := DecompressPrefix(raw, len(full), size)
			if err != nil || !bytes.Equal(prefix, full[:size]) {
				t.Fatalf("prefix %d/%d: %v", size, len(full), err)
			}
		}
		for _, bad := range []int{-1, len(full) + 1} {
			if _, err := DecompressPrefix(raw, len(full), bad); err == nil {
				t.Fatal("invalid prefix accepted")
			}
		}
	}
}

func FuzzPrefixMatchesCompleteDecode(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, uint8(64), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, size, cut uint8) {
		full, err := Decompress(data, int(size))
		if err != nil {
			return
		}
		limit := int(cut)
		if limit > len(full) {
			limit = len(full)
		}
		prefix, err := DecompressPrefix(data, len(full), limit)
		if err != nil || !bytes.Equal(prefix, full[:limit]) {
			t.Fatalf("prefix differs: %v", err)
		}
	})
}
