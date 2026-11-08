package uup

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/storage"
)

func assemblyFileSHA1(file AssemblyFile) (*[sha1.Size]byte, error) {
	if !strings.EqualFold(file.HashAlgorithm, "sha1") && !strings.EqualFold(file.HashAlgorithm, "sha-1") {
		return nil, nil
	}
	decoded, err := hex.DecodeString(file.Hash)
	if err != nil || len(decoded) != sha1.Size {
		return nil, fmt.Errorf("invalid assembly file SHA-1 digest")
	}
	// A nested digest is the payload declaration. Serviced .NET manifests can
	// retain a legacy build-time SHA-1 attribute that does not describe the
	// delivered file (WCF-System.Runtime.Serialization, 10.0.27000.398).
	// Keep validating its syntax, but never require it in addition to the
	// checked nested SHA-256. Without a nested digest SHA-1 remains binding.
	if file.Digest != nil {
		if _, err := assemblyNestedSHA256(file.Digest); err != nil {
			return nil, err
		}
		return nil, nil
	}
	var result [sha1.Size]byte
	copy(result[:], decoded)
	return &result, nil
}

func verifyLegacyFileDigest(file storage.Reader, effect StageFileEffect) error {
	if effect.ExpectedSHA1 == nil {
		return nil
	}
	digest := sha1.New()
	if _, err := io.Copy(digest, io.NewSectionReader(file, 0, file.Size())); err != nil {
		return err
	}
	var got [sha1.Size]byte
	copy(got[:], digest.Sum(nil))
	if got != *effect.ExpectedSHA1 {
		return fmt.Errorf("uup servicing: file %q does not match manifest SHA-1", effect.SourceName)
	}
	return nil
}
