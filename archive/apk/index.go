// Package apk reads the signed Alpine v2 repository index and package identity.
package apk

import (
	"archive/tar"
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	_ "crypto/sha256" // registers the RSA256 digest
	_ "crypto/sha512" // registers the RSA512 digest
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/archive/gzip"
	"github.com/tinyrange/trex/storage"
)

const indexLimit = 32 << 20

var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$`)

// Record describes one immutable APK identity advertised by a repository.
type Record struct {
	Name, Version, Architecture, Description string
	Size, InstalledSize                      int64
	Checksum                                 string
	Dependencies, Provides                   []string
	ProviderPriority                         int
}

func ValidIdentity(s string) bool { return identity.MatchString(s) }

// PublicKey parses an Alpine RSA repository key.
func PublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("apk: malformed public key")
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := value.(*rsa.PublicKey); ok {
		return key, nil
	}
	return nil, fmt.Errorf("apk: expected RSA public key")
}

// ReadIndex verifies the signed compressed data member before reading APKINDEX.
func ReadIndex(source storage.Reader, keys map[string]*rsa.PublicKey) ([]Record, error) {
	parts, err := gzip.Members(source, indexLimit, 2)
	if err != nil {
		return nil, fmt.Errorf("apk index: %w", err)
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf("apk index: expected signature and index")
	}
	if err := verifySignature(parts[0], parts[1], keys); err != nil {
		return nil, err
	}
	reader, err := memberTar(parts[1], indexLimit)
	if err != nil {
		return nil, err
	}
	var records []Record
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Name != "APKINDEX" {
			continue
		}
		if records != nil || h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("apk index: duplicate or invalid APKINDEX")
		}
		records, err = parseIndex(reader)
		if err != nil {
			return nil, err
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("apk index: no package records")
	}
	return records, nil
}

func parseIndex(r io.Reader) ([]Record, error) {
	scanner := bufio.NewScanner(r)
	// Packages with many virtual provides, such as texlive, have long rows.
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	records := []Record{}
	var row Record
	seen := make(map[byte]bool)
	flush := func() error {
		if len(seen) == 0 {
			return nil
		}
		check, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(row.Checksum, "Q1"))
		if !ValidIdentity(row.Name) || !ValidIdentity(row.Version) || !ValidIdentity(row.Architecture) ||
			row.Size <= 0 || !strings.HasPrefix(row.Checksum, "Q1") || err != nil || len(check) != sha1.Size {
			return fmt.Errorf("apk index: invalid package record %q", row.Name)
		}
		records = append(records, row)
		row = Record{}
		clear(seen)
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if len(line) < 2 || line[1] != ':' || seen[line[0]] {
			return nil, fmt.Errorf("apk index: invalid or repeated field")
		}
		key, value := line[0], line[2:]
		seen[key] = true
		var err error
		switch key {
		case 'P':
			row.Name = value
		case 'V':
			row.Version = value
		case 'A':
			row.Architecture = value
		case 'T':
			row.Description = value
		case 'S':
			row.Size, err = strconv.ParseInt(value, 10, 64)
		case 'I':
			row.InstalledSize, err = strconv.ParseInt(value, 10, 64)
		case 'C':
			row.Checksum = value
		case 'D':
			row.Dependencies = strings.Fields(value)
		case 'p':
			row.Provides = strings.Fields(value)
		case 'k':
			row.ProviderPriority, err = strconv.Atoi(value)
		}
		if err != nil {
			return nil, fmt.Errorf("apk index: invalid %c field: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return records, nil
}

// VerifyPackage checks a v2 package's signed compressed control member against
// a repository identity. Its signed SHA-256 datahash is checked by the payload
// reader before any contents are materialized.
func VerifyPackage(source storage.Reader, record Record, keys map[string]*rsa.PublicKey, limit int64) error {
	if source.Size() != record.Size {
		return fmt.Errorf("apk: size differs from index")
	}
	parts, err := gzip.Members(source, limit, 3)
	if err != nil {
		return err
	}
	if len(parts) != 3 {
		return fmt.Errorf("apk: expected signed version 2 package")
	}
	if err := verifySignature(parts[0], parts[1], keys); err != nil {
		return err
	}
	check := sha1.New()
	if _, err := io.Copy(check, io.NewSectionReader(parts[1], 0, parts[1].Size())); err != nil {
		return err
	}
	if "Q1"+base64.StdEncoding.EncodeToString(check.Sum(nil)) != record.Checksum {
		return fmt.Errorf("apk: control checksum differs from index")
	}
	return nil
}

func memberTar(member storage.Reader, limit int64) (*tar.Reader, error) {
	file, err := gzip.Materialize(member, limit)
	if err != nil {
		return nil, err
	}
	return tar.NewReader(io.NewSectionReader(file, 0, file.Size())), nil
}

func verifySignature(signatures, signed storage.Reader, keys map[string]*rsa.PublicKey) error {
	reader, err := memberTar(signatures, 64<<10)
	if err != nil {
		return err
	}
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			return fmt.Errorf("apk: no valid signature from a configured Alpine key")
		}
		if err != nil {
			return err
		}
		name, ok := strings.CutPrefix(hdr.Name, ".SIGN.")
		if !ok || hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("apk: invalid signature entry")
		}
		algorithm, keyID, _ := strings.Cut(name, ".")
		key := keys[keyID]
		if key == nil || hdr.Size != int64(key.Size()) {
			continue
		}
		hash := map[string]crypto.Hash{"RSA": crypto.SHA1, "RSA256": crypto.SHA256, "RSA512": crypto.SHA512}[algorithm]
		if hash == 0 {
			continue
		}
		digest := hash.New()
		if _, err := io.Copy(digest, io.NewSectionReader(signed, 0, signed.Size())); err != nil {
			return err
		}
		signature, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		if rsa.VerifyPKCS1v15(key, hash, digest.Sum(nil), signature) == nil {
			return nil
		}
	}
}
