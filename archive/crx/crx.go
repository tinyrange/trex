// Package crx reads signed Chrome extension packages through portable files.
package crx

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

const maximumHeader = 1 << 20

// Archive contains a verified CRX3 envelope and its borrowed ZIP contents.
// ID is bound to the developer public key. All supplied RSA/SHA-256 and
// P-256 ECDSA/SHA-256 proofs are verified; no publisher key is pinned.
type Archive struct {
	ID      string
	Version uint32
	ZIP     *zip.Reader
}

// Open verifies the signatures and reads the ZIP directory without extracting
// files. The caller must keep source open while using the returned entries.
func Open(source storage.Reader) (*Archive, error) {
	var prefix [12]byte
	if source.Size() < int64(len(prefix)) {
		return nil, fmt.Errorf("crx: truncated header")
	}
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, 12), prefix[:]); err != nil {
		return nil, fmt.Errorf("crx: read header: %w", err)
	}
	if string(prefix[:4]) != "Cr24" {
		return nil, fmt.Errorf("crx: invalid magic")
	}
	version := binary.LittleEndian.Uint32(prefix[4:8])
	if version != 3 {
		return nil, fmt.Errorf("crx: unsupported version %d (want CRX3)", version)
	}
	headerSize := int64(binary.LittleEndian.Uint32(prefix[8:]))
	if headerSize > maximumHeader || headerSize > source.Size()-12 {
		return nil, fmt.Errorf("crx: invalid header size %d", headerSize)
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(io.NewSectionReader(source, 12, headerSize), header); err != nil {
		return nil, fmt.Errorf("crx: read proofs: %w", err)
	}
	fields, err := protoFields(header)
	if err != nil {
		return nil, err
	}
	signed, err := singleBytes(fields, 10000)
	if err != nil {
		return nil, err
	}
	signedFields, err := protoFields(signed)
	if err != nil {
		return nil, err
	}
	id, err := singleBytes(signedFields, 1)
	if err != nil || len(id) != 16 {
		return nil, fmt.Errorf("crx: signed ID must contain 16 bytes")
	}
	payload := io.NewSectionReader(source, 12+headerSize, source.Size()-12-headerSize)
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("CRX3 SignedData\x00"))
	var signedSize [4]byte
	binary.LittleEndian.PutUint32(signedSize[:], uint32(len(signed)))
	_, _ = hasher.Write(signedSize[:])
	_, _ = hasher.Write(signed)
	if _, err := io.Copy(hasher, payload); err != nil {
		return nil, fmt.Errorf("crx: hash payload: %w", err)
	}
	digest := hasher.Sum(nil)
	developer := false
	for _, field := range fields {
		if field.number != 2 && field.number != 3 {
			continue
		}
		if field.wire != 2 {
			return nil, fmt.Errorf("crx: invalid proof wire type")
		}
		proof, err := protoFields(field.data)
		if err != nil {
			return nil, err
		}
		keyBytes, err := singleBytes(proof, 1)
		if err != nil {
			return nil, err
		}
		signature, err := singleBytes(proof, 2)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("crx: invalid proof key: %w", err)
		}
		valid := false
		if field.number == 2 {
			if rsaKey, ok := key.(*rsa.PublicKey); ok {
				valid = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest, signature) == nil
			}
		} else if ecKey, ok := key.(*ecdsa.PublicKey); ok && ecKey.Curve == elliptic.P256() {
			valid = ecdsa.VerifyASN1(ecKey, digest, signature)
		}
		if !valid {
			return nil, fmt.Errorf("crx: invalid signature")
		}
		keyHash := sha256.Sum256(keyBytes)
		developer = developer || bytes.Equal(keyHash[:16], id)
	}
	if !developer {
		return nil, fmt.Errorf("crx: missing developer proof for signed ID")
	}
	zipReader, err := zip.NewReader(payload, payload.Size())
	if err != nil {
		return nil, fmt.Errorf("crx: ZIP directory: %w", err)
	}
	return &Archive{ID: encodeID(id), Version: version, ZIP: zipReader}, nil
}

func encodeID(id []byte) string {
	result := make([]byte, len(id)*2)
	for i, value := range id {
		result[i*2], result[i*2+1] = 'a'+(value>>4), 'a'+(value&15)
	}
	return string(result)
}

type protoField struct {
	number uint64
	wire   uint64
	data   []byte
}

// Only the small CRX header messages are decoded. Unknown scalar and byte
// fields are skipped; groups are rejected rather than recursively allocated.
func protoFields(data []byte) ([]protoField, error) {
	var fields []protoField
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
			return nil, fmt.Errorf("crx: invalid protobuf tag")
		}
		data = data[n:]
		field := protoField{number: tag >> 3, wire: tag & 7}
		var length uint64
		switch field.wire {
		case 0:
			_, n = binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("crx: invalid protobuf integer")
			}
			length = uint64(n)
		case 1:
			length = 8
		case 2:
			length, n = binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("crx: invalid protobuf length")
			}
			data = data[n:]
		case 5:
			length = 4
		default:
			return nil, fmt.Errorf("crx: unsupported protobuf wire type %d", field.wire)
		}
		if length > uint64(len(data)) {
			return nil, fmt.Errorf("crx: truncated protobuf field")
		}
		field.data = data[:length]
		data = data[length:]
		fields = append(fields, field)
	}
	return fields, nil
}

func singleBytes(fields []protoField, number uint64) ([]byte, error) {
	var result []byte
	found := false
	for _, field := range fields {
		if field.number == number {
			if found || field.wire != 2 {
				return nil, fmt.Errorf("crx: duplicate or invalid protobuf field %d", number)
			}
			found, result = true, field.data
		}
	}
	if !found {
		return nil, fmt.Errorf("crx: missing protobuf field %d", number)
	}
	return result, nil
}
