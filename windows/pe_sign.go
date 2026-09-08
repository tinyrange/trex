package windows

// Authenticode is PKCS #7 (RFC 2315), not CMS's OCTET STRING encapsulation.
// Format references and interoperability limits are documented in
// docs/pe-signing.md. This implementation uses only Go's standard library.
import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"time"

	"go.starlark.net/starlark"
)

var (
	spcIndirectOID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	spcPEImageOID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	spcStatementOID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	spcIndividualOID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}
	spcOpusOID           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	pkcsContentTypeOID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	pkcsMessageDigestOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	sha256OID            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	rsaEncryptionOID     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// Private key material is deliberately absent from String and Attr.
type peSigningIdentity struct {
	certificate *x509.Certificate
	key         *rsa.PrivateKey
	chain       []*x509.Certificate
}

func (*peSigningIdentity) String() string        { return "<windows.signing_identity>" }
func (*peSigningIdentity) Type() string          { return "windows.signing_identity" }
func (*peSigningIdentity) Freeze()               {}
func (*peSigningIdentity) Truth() starlark.Bool  { return starlark.True }
func (*peSigningIdentity) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable signing identity") }
func (s *peSigningIdentity) Attr(name string) (starlark.Value, error) {
	if name == "certificate" {
		return starlark.Bytes(s.certificate.Raw), nil
	}
	return nil, nil
}
func (*peSigningIdentity) AttrNames() []string { return []string{"certificate"} }

func signingDER(value starlark.Value, name string) ([]byte, error) {
	data, err := bytesForBinaryValueLimited(value, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
			return nil, fmt.Errorf("%s: expected one unencrypted PEM block", name)
		}
		return block.Bytes, nil
	}
	return data, nil
}

func signingIdentityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var certValue, keyValue starlark.Value
	var chainValue starlark.Iterable = starlark.Tuple{}
	if err := starlark.UnpackArgs("signing_identity", args, kwargs, "certificate", &certValue, "private_key", &keyValue, "chain?", &chainValue); err != nil {
		return nil, err
	}
	certDER, err := signingDER(certValue, "certificate")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	keyDER, err := signingDER(keyValue, "private_key")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(keyDER)
		if parseErr != nil {
			return nil, fmt.Errorf("private_key: expected unencrypted PKCS#1 or PKCS#8 RSA key")
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private_key: only RSA signing is supported")
		}
	}
	identity := &peSigningIdentity{certificate: cert, key: key}
	it := chainValue.Iterate()
	defer it.Done()
	var value starlark.Value
	for it.Next(&value) {
		if len(identity.chain) >= 16 {
			return nil, fmt.Errorf("chain exceeds 16 certificates")
		}
		der, err := signingDER(value, "chain certificate")
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("chain certificate: %w", err)
		}
		identity.chain = append(identity.chain, cert)
	}
	if err := identity.validate(); err != nil {
		return nil, err
	}
	return identity, nil
}

func (s *peSigningIdentity) validate() error {
	if s == nil || s.certificate == nil || s.key == nil {
		return fmt.Errorf("missing signing identity")
	}
	if s.key.N.BitLen() < 2048 || s.key.N.BitLen() > 8192 {
		return fmt.Errorf("RSA key must be between 2048 and 8192 bits")
	}
	if err := s.key.Validate(); err != nil {
		return fmt.Errorf("invalid RSA private key")
	}
	pub, ok := s.certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(s.key.Public()) {
		return fmt.Errorf("certificate does not match RSA private key")
	}
	if s.certificate.KeyUsage != 0 && s.certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate does not allow digital signatures")
	}
	if len(s.certificate.ExtKeyUsage)+len(s.certificate.UnknownExtKeyUsage) != 0 {
		allowed := false
		for _, usage := range s.certificate.ExtKeyUsage {
			allowed = allowed || usage == x509.ExtKeyUsageCodeSigning || usage == x509.ExtKeyUsageAny
		}
		if !allowed {
			return fmt.Errorf("certificate does not allow code signing")
		}
	}
	return nil
}

func testSigningIdentityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var subject string
	var before, after int64
	if err := starlark.UnpackArgs("test_signing_identity", args, kwargs, "subject", &subject, "not_before", &before, "not_after", &after); err != nil {
		return nil, err
	}
	if subject == "" || len(subject) > 256 || before < 0 || after <= before || after > 253402300799 {
		return nil, fmt.Errorf("invalid subject or certificate validity interval (Unix seconds)")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, NotBefore: time.Unix(before, 0), NotAfter: time.Unix(after, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true, SignatureAlgorithm: x509.SHA256WithRSA}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &peSigningIdentity{certificate: cert, key: key}, nil
}

// Small DER constructors accept only already-encoded elements. SET OF values
// are sorted by their complete DER encoding, as required by X.690.
func signingTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	if len(content) < 128 {
		out = append(out, byte(len(content)))
	} else {
		var buf [8]byte
		n, size := 0, len(content)
		for size != 0 {
			n++
			buf[8-n] = byte(size)
			size >>= 8
		}
		out = append(out, 0x80|byte(n))
		out = append(out, buf[8-n:]...)
	}
	return append(out, content...)
}
func signingSequence(elements ...[]byte) []byte { return signingTLV(0x30, bytes.Join(elements, nil)) }
func signingSet(elements ...[]byte) []byte {
	sort.Slice(elements, func(i, j int) bool { return bytes.Compare(elements[i], elements[j]) < 0 })
	return signingTLV(0x31, bytes.Join(elements, nil))
}
func signingOID(oid asn1.ObjectIdentifier) []byte { data, _ := asn1.Marshal(oid); return data }
func signingAlgorithm(oid asn1.ObjectIdentifier) []byte {
	return signingSequence(signingOID(oid), []byte{5, 0})
}
func signingAttribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	return signingSequence(signingOID(oid), signingSet(value))
}

func signAuthenticodeDigest(digest []byte, identity *peSigningIdentity, pageHashes ...[]byte) ([]byte, error) {
	// SpcPeImageData includes the ignored flags and an empty file SpcString.
	// Authenticode's published ASN.1 differs from Microsoft's wire encoding:
	// SpcAttributeTypeAndOptionalValue.value is a direct SEQUENCE, and the
	// SpcPeImageData.file choice is wrapped in [0]. See the format note.
	imageData := signingSequence([]byte{3, 1, 0}, signingTLV(0xa0, signingTLV(0xa2, []byte{0x80, 0})))
	if len(pageHashes) != 0 && len(pageHashes[0]) != 0 {
		imageData = pePageHashImageData(pageHashes[0])
	}
	indirect := signingSequence(signingSequence(signingOID(spcPEImageOID), imageData), signingSequence(signingAlgorithm(sha256OID), signingTLV(4, digest)))
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(indirect, &raw); err != nil {
		return nil, err
	}
	// RFC 2315 section 9.3: hash the content's value octets, excluding its
	// enclosing SEQUENCE tag and length. Authenticated attributes use SET OF.
	contentHash := sha256.Sum256(raw.Bytes)
	attrs := signingSet(
		signingAttribute(pkcsContentTypeOID, signingOID(spcIndirectOID)),
		signingAttribute(pkcsMessageDigestOID, signingTLV(4, contentHash[:])),
		signingAttribute(spcStatementOID, signingSequence(signingOID(spcIndividualOID))),
		signingAttribute(spcOpusOID, signingSequence()),
	)
	attrsHash := sha256.Sum256(attrs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, identity.key, crypto.SHA256, attrsHash[:])
	if err != nil {
		return nil, err
	}
	attrs[0] = 0xa0 // IMPLICIT [0] replaces the SET tag only after signing.
	serial, err := asn1.Marshal(identity.certificate.SerialNumber)
	if err != nil {
		return nil, err
	}
	version := []byte{2, 1, 1}
	signer := signingSequence(version, signingSequence(identity.certificate.RawIssuer, serial), signingAlgorithm(sha256OID), attrs, signingAlgorithm(rsaEncryptionOID), signingTLV(4, sig))
	certs := [][]byte{identity.certificate.Raw}
	for _, cert := range identity.chain {
		certs = append(certs, cert.Raw)
	}
	certSet := signingSet(certs...)
	certSet[0] = 0xa0
	signedData := signingSequence(version, signingSet(signingAlgorithm(sha256OID)), signingSequence(signingOID(spcIndirectOID), signingTLV(0xa0, indirect)), certSet, signingSet(signer))
	return signingSequence(signingOID(pkcs7SignedDataOID), signingTLV(0xa0, signedData)), nil
}

type peSigningLayout struct{ security, certificate, certificateSize, hashedSize int }

func signingPELayout(data []byte) (peSigningLayout, error) {
	var layout peSigningLayout
	regions, err := authenticodePERanges(data)
	if err != nil {
		return layout, err
	}
	pe := int(binary.LittleEndian.Uint32(data[0x3c:]))
	opt := pe + 24
	end := opt + int(binary.LittleEndian.Uint16(data[pe+20:]))
	count := opt + 92
	if binary.LittleEndian.Uint16(data[opt:]) == 0x20b {
		count = opt + 108
	}
	layout.security = count + 4 + 32
	if layout.security+8 > end || binary.LittleEndian.Uint32(data[count:]) < 5 {
		return layout, fmt.Errorf("PE has no certificate-table directory slot")
	}
	layout.certificate = int(binary.LittleEndian.Uint32(data[layout.security:]))
	layout.certificateSize = int(binary.LittleEndian.Uint32(data[layout.security+4:]))
	// The existing catalog helper deliberately hashes only headers/sections.
	// Authenticode_PE.docx's signing algorithm adds a final extra-data range
	// starting at SizeOfHeaders + sum(SizeOfRawData), excluding certificates.
	layout.hashedSize = int(binary.LittleEndian.Uint32(data[opt+60:]))
	headers := layout.hashedSize
	for _, region := range regions {
		if region.offset >= headers {
			layout.hashedSize += region.size
		}
	}
	if layout.certificate == 0 && layout.certificateSize == 0 {
		return layout, nil
	}
	if layout.certificate < headers || layout.certificate%8 != 0 || layout.certificateSize < 8 || layout.certificateSize%8 != 0 || layout.certificate > len(data) || layout.certificateSize != len(data)-layout.certificate {
		return layout, fmt.Errorf("certificate table must be aligned, bounded, and at end of file")
	}
	for _, region := range regions {
		if region.offset+region.size > layout.certificate {
			return layout, fmt.Errorf("certificate table overlaps image data")
		}
	}
	for pos := layout.certificate; pos < len(data); {
		if len(data)-pos < 8 {
			return layout, fmt.Errorf("truncated WIN_CERTIFICATE header")
		}
		size := uint64(binary.LittleEndian.Uint32(data[pos:]))
		aligned := (size + 7) &^ 7
		if size < 8 || aligned > uint64(len(data)-pos) {
			return layout, fmt.Errorf("invalid WIN_CERTIFICATE length")
		}
		pos += int(aligned)
	}
	return layout, nil
}

func peSigningDigest(data []byte, layout peSigningLayout) ([]byte, error) {
	regions, err := authenticodePERanges(data)
	if err != nil {
		return nil, err
	}
	end := len(data) - layout.certificateSize
	if layout.hashedSize > end {
		return nil, fmt.Errorf("PE hashed data exceeds certificate offset")
	}
	h := sha256.New()
	for _, region := range regions {
		h.Write(data[region.offset : region.offset+region.size])
	}
	h.Write(data[layout.hashedSize:end])
	return h.Sum(nil), nil
}

func signPE(data []byte, identity *peSigningIdentity, replace bool) ([]byte, error) {
	return signPEWithPageHashes(data, identity, replace, false)
}

func signPEWithPageHashes(data []byte, identity *peSigningIdentity, replace, includePageHashes bool) ([]byte, error) {
	if err := identity.validate(); err != nil {
		return nil, err
	}
	layout, err := signingPELayout(data)
	if err != nil {
		return nil, err
	}
	if layout.certificateSize != 0 && !replace {
		return nil, fmt.Errorf("PE already has a certificate table; use replace=True to replace it")
	}
	end := len(data) - layout.certificateSize
	out := make([]byte, (end+7)&^7)
	copy(out, data[:end])
	clear(out[layout.security : layout.security+8])
	layout.certificate, layout.certificateSize = 0, 0
	digest, err := peSigningDigest(out, layout)
	if err != nil {
		return nil, err
	}
	var pageHashes []byte
	if includePageHashes {
		pageHashes, err = pePageHashes(out)
		if err != nil {
			return nil, err
		}
	}
	pkcs7, err := signAuthenticodeDigest(digest, identity, pageHashes)
	if err != nil {
		return nil, err
	}
	entry := make([]byte, (8+len(pkcs7)+7)&^7)
	binary.LittleEndian.PutUint32(entry, uint32(len(entry)))
	binary.LittleEndian.PutUint16(entry[4:], 0x200)
	binary.LittleEndian.PutUint16(entry[6:], 2)
	copy(entry[8:], pkcs7)
	if uint64(len(out))+uint64(len(entry)) > 0xffffffff {
		return nil, fmt.Errorf("signed PE exceeds 32-bit file offsets")
	}
	binary.LittleEndian.PutUint32(out[layout.security:], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[layout.security+4:], uint32(len(entry)))
	out = append(out, entry...)
	if err := updatePEChecksum(out); err != nil {
		return nil, err
	}
	return out, nil
}

func peSignBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var identity *peSigningIdentity
	var replace, pageHashes bool
	if err := starlark.UnpackArgs("pe_sign", args, kwargs, "file", &value, "identity", &identity, "replace?", &replace, "page_hashes?", &pageHashes); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, err
	}
	out, err := signPEWithPageHashes(data, identity, replace, pageHashes)
	if err != nil {
		return nil, fmt.Errorf("pe_sign: %w", err)
	}
	return starlark.Bytes(out), nil
}
