package crx

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func protoBytes(number uint64, data []byte) []byte {
	out := binary.AppendUvarint(nil, number<<3|2)
	out = binary.AppendUvarint(out, uint64(len(data)))
	return append(out, data...)
}

func signedPackage(t *testing.T, algorithm string) ([]byte, string) {
	t.Helper()
	var payload bytes.Buffer
	writer := zip.NewWriter(&payload)
	entry, err := writer.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte(`{"name":"Test","version":"1.2","manifest_version":3}`))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var signer crypto.Signer
	var field uint64 = 3
	if algorithm == "rsa" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signer, field = key, 2
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer = key
	}
	key, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(key)
	signed := protoBytes(1, keyHash[:16])
	message := append([]byte("CRX3 SignedData\x00"), binary.LittleEndian.AppendUint32(nil, uint32(len(signed)))...)
	message = append(message, signed...)
	message = append(message, payload.Bytes()...)
	digest := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	proof := append(protoBytes(1, key), protoBytes(2, signature)...)
	header := append(protoBytes(field, proof), protoBytes(10000, signed)...)
	file := binary.LittleEndian.AppendUint32([]byte("Cr24"), 3)
	file = binary.LittleEndian.AppendUint32(file, uint32(len(header)))
	file = append(file, header...)
	return append(file, payload.Bytes()...), encodeID(keyHash[:16])
}

func TestOpenAndStarlark(t *testing.T) {
	for _, algorithm := range []string{"rsa", "ecdsa"} {
		t.Run(algorithm, func(t *testing.T) {
			data, id := signedPackage(t, algorithm)
			file := &starfile.Bytes{Data: data}
			archive, err := Open(file)
			if err != nil {
				t.Fatal(err)
			}
			if archive.ID != id || archive.Version != 3 || len(archive.ZIP.File) != 1 {
				t.Fatalf("wrong archive: %+v", archive)
			}
			reader, err := archive.ZIP.File[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil || !bytes.Contains(body, []byte(`"version":"1.2"`)) {
				t.Fatalf("payload: %s, %v", body, err)
			}
			value, err := Builtin(nil, nil, starlark.Tuple{file}, nil)
			if err != nil || value.(*starfile.Record).Get("id") != starlark.String(id) {
				t.Fatalf("Starlark result: %v, %v", value, err)
			}
			data[len(data)-1] ^= 1
			if _, err := Open(file); err == nil || !strings.Contains(err.Error(), "signature") {
				t.Fatalf("tampered payload accepted: %v", err)
			}
		})
	}
}

func TestMalformedCRX(t *testing.T) {
	data, _ := signedPackage(t, "ecdsa")
	for _, length := range []int{0, 4, 11, 12, 30, len(data) - 1} {
		if _, err := Open(&starfile.Bytes{Data: data[:length]}); err == nil {
			t.Errorf("accepted truncated length %d", length)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 'X' },
		func(b []byte) { binary.LittleEndian.PutUint32(b[4:8], 2) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], maximumHeader+1) },
		func(b []byte) { b[12] = 0 },
	} {
		copyData := bytes.Clone(data)
		mutate(copyData)
		if _, err := Open(&starfile.Bytes{Data: copyData}); err == nil {
			t.Error("accepted malformed CRX")
		}
	}
	for _, header := range [][]byte{
		{0xff}, {0x0a, 0xff}, {0x0b}, {0x09, 0x00},
		append(protoBytes(1, []byte{1}), protoBytes(1, []byte{2})...),
	} {
		fields, err := protoFields(header)
		if err == nil {
			_, err = singleBytes(fields, 1)
		}
		if err == nil {
			t.Errorf("accepted malformed protobuf %x", header)
		}
	}
	// A signed ID without a corresponding developer proof must be rejected.
	signed := protoBytes(1, make([]byte, 16))
	header := protoBytes(10000, signed)
	file := binary.LittleEndian.AppendUint32([]byte("Cr24"), 3)
	file = binary.LittleEndian.AppendUint32(file, uint32(len(header)))
	if _, err := Open(&starfile.Bytes{Data: append(file, header...)}); err == nil || !strings.Contains(err.Error(), "developer proof") {
		t.Fatalf("missing proof: %v", err)
	}
}
