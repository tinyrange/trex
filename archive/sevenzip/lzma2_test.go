package sevenzip

import (
	"bytes"
	"encoding/hex"
	"hash/crc32"
	"io"
	"testing"
)

// Raw LZMA2 payload of XZ Utils' public-domain good-1-lzma2-1.xz.
// Fixture provenance and dedication: https://github.com/tukaani-project/xz/tree/master/tests/files
// Two compressed chunks, with new properties on the second chunk.
const lzma2PropertyResetFixture = "e000e200b65d00261bca46675af277b87d86d841db0535cd83a57c12a505db90bd2f14d3717296a88a7d8456718d6a2298ab9e3d90802dc75e0c1252d33f07087b1ca477f313b817c0ee918139b387f0ff00b36a5241ed2eb0f26497a49a9e63a1ae19740da9d55b6ceeb1e02cdc61dccb9d86cfe1dc0a7a81145fd040c87e0d9744ceb5c2fc2c5908bf0380dcd7448eb3d42ddee516216e4782ac0859d8e4662961d5d1fa496390113e20d0a9e2d51481d923d08f43ae45553669aa00c000e500ad0b008cf19d402bd07d1d99eee4dc63746446a4a04a6465b2f64ec1c8689f2754adbba6343c77ec0f2e1b8e4227e568bf60f40b3af09b31ebdf3fd8afa5559246055822098fa860080ba3e93ebcb416dbc7a3a2c016d514a722e82fe8b4d07717c58be4f2bb6bd6ef9a81344e1ddcec36e64472bf29b53c05316066ba2c030fd647c67d85d4c55e4e5773c34169be0d8c9cb515a9e7d278514bd529d0f9351ac55df48c7a70d55ea8315780c8a5d8e000"

func TestLZMA2CompressedPropertyReset(t *testing.T) {
	data, err := hex.DecodeString(lzma2PropertyResetFixture)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newLZMA2Reader(bytes.NewReader(data), []byte{8}, 457, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise partial reads across decoded chunk boundaries.
	var output bytes.Buffer
	buffer := make([]byte, 7)
	if _, err := io.CopyBuffer(struct{ io.Writer }{&output}, r, buffer); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 457 || crc32.ChecksumIEEE(output.Bytes()) != 0xdb4847fb {
		t.Fatalf("decoded length=%d CRC=%08x", output.Len(), crc32.ChecksumIEEE(output.Bytes()))
	}
	for n := 0; n < len(data); n++ {
		r, err := newLZMA2Reader(bytes.NewReader(data[:n]), []byte{8}, 457, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadAll(r); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}

func TestLZMA2Framing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		size    uint64
		want    string
		invalid bool
	}{
		{"empty", []byte{0}, 0, "", false},
		{"plain", []byte{1, 0, 1, 'a', 'b', 2, 0, 0, 'c', 0}, 3, "abc", false},
		{"dictionary reset", []byte{1, 0, 0, 'a', 1, 0, 0, 'b', 0}, 2, "ab", false},
		{"missing dictionary", []byte{2, 0, 0, 'a', 0}, 1, "", true},
		{"reserved control", []byte{3}, 1, "", true},
		{"early end", []byte{0}, 1, "", true},
		{"size overflow", []byte{1, 0, 1, 'a', 'b', 0}, 1, "", true},
		{"missing end", []byte{1, 0, 0, 'a'}, 1, "", true},
		{"missing properties", []byte{1, 0, 0, 'a', 0x80, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0}, 2, "", true},
		{"invalid properties", []byte{0xe0, 0, 0, 0, 4, 225, 0, 0, 0, 0, 0, 0}, 1, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := newLZMA2Reader(bytes.NewReader(tc.data), []byte{0}, tc.size, 4096)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted malformed stream")
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
	for _, prop := range [][]byte{nil, {41}, {0, 0}} {
		if _, err := newLZMA2Reader(bytes.NewReader(nil), prop, 1, 4096); err == nil {
			t.Fatalf("accepted properties %x", prop)
		}
	}
	if _, err := newLZMA2Reader(bytes.NewReader(nil), []byte{1}, 1, 4096); err == nil {
		t.Fatal("ignored dictionary limit")
	}
}

func TestLZMA2DictionaryResetThroughPlainChunk(t *testing.T) {
	// XZ Utils public-domain good-1-lzma2-4.xz payload: compressed,
	// dictionary-resetting plain chunk, compressed with fresh properties.
	data, err := hex.DecodeString("e000bb00a15d00261bca46675af277b87d86d841db0535cd83a57c12a505db90bd2f14d3717296a88a7d8456718d6a2298ab9e3d90802dc75e0c1252d33f07087b1ca477f313b817c0ee9173cabccfeb3466ac489b69d99307aece50af68092f5b881fc208a22c5845b0ff6209ebeedb634f6fe0f31fcf123798964ef6f2b2fb6eaf4402e222ded5e6349739a3452fae992f79698fe9378948fecc7eeaa928adc3e6dcb9daaa167e0100266c61626f726973206e69736920757420616c697175697020657820656120636f6d6d6f646f200ac000e500bd5d00319bca19c554ecb654e7b17dc4579e6c89ad4a6d16d83c05941016993821a3b9c580fffceed4d53fdd8cd73d8f76ec88aa32ab65d438eff7f98abff7f8a556d76dd73f850b9e3fe2476822080535b84172f9dbbeb78e86bf434b8e0d432f4169df610cc4e837084adec27616b8484e9eb953501f3383e829a067c8663a7f221262fb47e4bcf4510f158849d8ca0b258b5ee8dafd38c0ce4c731bffd09be84cb713f83799e2da9c2fb5eab8a58dea57829b25cafbf6880a9bdf41036e0000")
	if err != nil {
		t.Fatal(err)
	}
	r, err := newLZMA2Reader(bytes.NewReader(data), []byte{8}, 457, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 457 || crc32.ChecksumIEEE(output) != 0xdb4847fb {
		t.Fatalf("length=%d CRC=%08x", len(output), crc32.ChecksumIEEE(output))
	}
}
