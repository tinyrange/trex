package crypto

import (
	"encoding/hex"
	"testing"

	"go.starlark.net/starlark"
)

func TestCryptoHashKnownAnswers(t *testing.T) {
	tests := []struct {
		algorithm string
		input     string
		want      string
	}{
		{"md4", "", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"md4", "abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"md5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, test := range tests {
		h, err := newHash(test.algorithm)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write([]byte(test.input))
		if got := hex.EncodeToString(h.Sum(nil)); got != test.want {
			t.Errorf("%s(%q) = %s, want %s", test.algorithm, test.input, got, test.want)
		}
	}
}

func TestCryptoSHA256BlocksKnownAnswer(t *testing.T) {
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	block := make([]byte, 64)
	copy(block, "abc")
	block[3] = 0x80
	block[63] = 24
	value, err := cryptoHashBlocksBuiltin(nil, nil, starlark.Tuple{
		starlark.String("sha256"), starlark.Bytes(state), starlark.Bytes(block),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString([]byte(value.(starlark.Bytes))); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("SHA-256 block compression = %s", got)
	}
}

func TestCRC32Bzip2KnownAnswer(t *testing.T) {
	if got := crc32Bzip2([]byte("123456789")); got != 0xfc891918 {
		t.Fatalf("CRC-32/BZIP2 = %08x, want fc891918", got)
	}
	value, err := cryptoChecksumBuiltin(nil, nil, starlark.Tuple{
		starlark.String("crc32-bzip2"), starlark.Bytes("123456789"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := value.(starlark.Int).Uint64()
	if !ok || got != 0xfc891918 {
		t.Fatalf("crypto.checksum CRC-32/BZIP2 = %v", value)
	}
}

func TestCryptoBulkPrimitives(t *testing.T) {
	aesKey, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	aesIV, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	aesPlain, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	aesEncrypted, err := cryptoAESBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes(aesKey), starlark.Bytes(aesPlain),
	}, []starlark.Tuple{{starlark.String("iv"), starlark.Bytes(aesIV)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString([]byte(aesEncrypted.(starlark.Bytes))); got != "7649abac8119b246cee98e9b12e9197d" {
		t.Fatalf("AES-CBC = %s", got)
	}
	aesDecrypted, err := cryptoAESBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes(aesKey), aesEncrypted,
	}, []starlark.Tuple{
		{starlark.String("decrypt"), starlark.True},
		{starlark.String("iv"), starlark.Bytes(aesIV)},
	})
	if err != nil || aesDecrypted != starlark.Bytes(aesPlain) {
		t.Fatalf("AES-CBC round trip = %v, err %v", aesDecrypted, err)
	}

	key := starlark.Bytes("12345678")
	plain := starlark.Bytes("abcdefghABCDEFGH")
	encrypted, err := cryptoDESBuiltin(nil, nil, starlark.Tuple{key, plain}, []starlark.Tuple{
		{starlark.String("iv"), starlark.Bytes("87654321")},
	})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cryptoDESBuiltin(nil, nil, starlark.Tuple{key, encrypted}, []starlark.Tuple{
		{starlark.String("decrypt"), starlark.True},
		{starlark.String("iv"), starlark.Bytes("87654321")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plain {
		t.Fatalf("DES round trip = %v, want %v", decrypted, plain)
	}

	rc4Ciphertext, err := cryptoRC4Builtin(nil, nil, starlark.Tuple{starlark.Bytes("Key"), starlark.Bytes("Plaintext")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString([]byte(rc4Ciphertext.(starlark.Bytes))); got != "bbf316e8d940af0ad3" {
		t.Fatalf("RC4 = %s", got)
	}

	first, err := cryptoDeterministicBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("seed"), starlark.MakeInt(96)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cryptoDeterministicBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("seed"), starlark.MakeInt(96)}, nil)
	if err != nil || first != second {
		t.Fatalf("deterministic output mismatch: %v", err)
	}
}

func TestCryptoModInverse(t *testing.T) {
	value, err := cryptoModInverseBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(-3), starlark.MakeInt(17)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(starlark.Int).Int64(); !ok || got != 11 {
		t.Fatalf("mod_inverse(-3, 17) = %v, want 11", value)
	}
	value, err = cryptoModInverseBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(6), starlark.MakeInt(9)}, nil)
	if err != nil || value != starlark.None {
		t.Fatalf("mod_inverse(6, 9) = %v, %v; want None", value, err)
	}
}

func TestCryptoModExpFixedWidth(t *testing.T) {
	value, err := cryptoModExpBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes("\x00\x04"),
		starlark.Bytes("\x00\x0d"),
		starlark.Bytes("\x01\xf1"),
	}, nil)
	if err != nil || value != starlark.Bytes("\x01\xbd") {
		t.Fatalf("mod_exp big endian = %v, %v", value, err)
	}
	value, err = cryptoModExpBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes("\x04\x00"),
		starlark.Bytes("\x0d\x00"),
		starlark.Bytes("\xf1\x01"),
	}, []starlark.Tuple{{starlark.String("byte_order"), starlark.String("little")}})
	if err != nil || value != starlark.Bytes("\xbd\x01") {
		t.Fatalf("mod_exp little endian = %v, %v", value, err)
	}
}

func TestCryptoModMulFixedWidth(t *testing.T) {
	value, err := cryptoModMulBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes("\x00\x7b"),
		starlark.Bytes("\x01\xc8"),
		starlark.Bytes("\x01\xf1"),
	}, nil)
	if err != nil || value != starlark.Bytes("\x01\xa8") {
		t.Fatalf("mod_mul big endian = %v, %v", value, err)
	}
	value, err = cryptoModMulBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes("\x7b\x00"),
		starlark.Bytes("\xc8\x01"),
		starlark.Bytes("\xf1\x01"),
	}, []starlark.Tuple{{starlark.String("byte_order"), starlark.String("little")}})
	if err != nil || value != starlark.Bytes("\xa8\x01") {
		t.Fatalf("mod_mul little endian = %v, %v", value, err)
	}
}

func TestCryptoXTEAKnownAnswerAndRoundTrip(t *testing.T) {
	key := starlark.Bytes(make([]byte, 16))
	plain := starlark.Bytes(make([]byte, 8))
	encrypted, err := cryptoXTEABuiltin(nil, nil, starlark.Tuple{key, plain}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString([]byte(encrypted.(starlark.Bytes))); got != "dee9d4d8f7131ed9" {
		t.Fatalf("XTEA = %s, want dee9d4d8f7131ed9", got)
	}
	decrypted, err := cryptoXTEABuiltin(nil, nil, starlark.Tuple{key, encrypted}, []starlark.Tuple{
		{starlark.String("decrypt"), starlark.True},
	})
	if err != nil || decrypted != plain {
		t.Fatalf("XTEA round trip = %v, err %v", decrypted, err)
	}
}
