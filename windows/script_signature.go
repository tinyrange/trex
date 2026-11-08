package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

var powershellSIPUUID = []byte{0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51}

func scriptUTF16(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func scriptSignatureParts(data []byte, format string) ([]byte, []byte, error) {
	if len(data) > 16<<20 {
		return nil, nil, fmt.Errorf("script exceeds 16 MiB")
	}
	text := string(data)
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) {
		if len(data)%2 != 0 {
			return nil, nil, fmt.Errorf("odd UTF-16 script length")
		}
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(data[2*i:])
		}
		text = string(utf16.Decode(units))
		if !bytes.Equal(scriptUTF16(text), data) {
			return nil, nil, fmt.Errorf("invalid UTF-16 script")
		}
	} else if !utf8.Valid(data) {
		return nil, nil, fmt.Errorf("script must be UTF-8 or BOM-marked UTF-16LE")
	}
	open, close := "# ", ""
	if format == "xml" {
		open, close = "<!-- ", " -->"
	} else if format != "powershell" {
		return nil, nil, fmt.Errorf("unsupported script comment format")
	}
	begin := open + "SIG # Begin signature block" + close
	end := open + "SIG # End signature block" + close
	if strings.Count(text, begin) != 1 || strings.Count(text, end) != 1 {
		return nil, nil, fmt.Errorf("missing or ambiguous script signature block")
	}
	offset := strings.Index(text, begin)
	if offset < 2 || text[offset-2:offset] != "\r\n" {
		return nil, nil, fmt.Errorf("script signature requires preceding CRLF")
	}
	body := text[:offset-2]
	block := text[offset:]
	if !strings.HasSuffix(block, end+"\r\n") {
		return nil, nil, fmt.Errorf("trailing data after script signature")
	}
	lines := strings.Split(block, "\r\n")
	if len(lines) < 4 || lines[0] != begin || lines[len(lines)-2] != end || lines[len(lines)-1] != "" {
		return nil, nil, fmt.Errorf("invalid script signature framing")
	}
	var encoded strings.Builder
	for _, line := range lines[1 : len(lines)-2] {
		if !strings.HasPrefix(line, open) || !strings.HasSuffix(line, close) || len(line) < len(open)+len(close) {
			return nil, nil, fmt.Errorf("invalid script signature comment")
		}
		payload := line[len(open) : len(line)-len(close)]
		if len(payload) == 0 || len(payload) > 64 {
			return nil, nil, fmt.Errorf("invalid script signature line length")
		}
		encoded.WriteString(payload)
	}
	if encoded.Len() > 6<<20 {
		return nil, nil, fmt.Errorf("script signature exceeds limit")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded.String())
	if err != nil {
		return nil, nil, err
	}
	return scriptUTF16(body), signature, nil
}

func verifyScriptIntegrity(data []byte, format string) (*verifiedPEIntegrity, error) {
	body, signature, err := scriptSignatureParts(data, format)
	if err != nil {
		return nil, err
	}
	var outer signatureContent
	if err := signatureDER(signature, &outer); err != nil {
		return nil, err
	}
	if !outer.Type.Equal(pkcs7SignedDataOID) {
		return nil, fmt.Errorf("script signature is not SignedData")
	}
	var sd signatureSignedData
	if err := signatureDER(outer.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	if sd.Version != 1 || !sd.Content.Type.Equal(spcIndirectOID) {
		return nil, fmt.Errorf("unsupported script SignedData")
	}
	var indirect signatureIndirect
	if err := signatureDER(sd.Content.Content.Bytes, &indirect); err != nil {
		return nil, err
	}
	if !indirect.Data.Type.Equal(appxSIPOID) || !signatureAlgorithm(indirect.Digest.Algorithm, sha256OID) {
		return nil, fmt.Errorf("unsupported script SIP or digest")
	}
	var sip appxSIPInfo
	if err := signatureDER(indirect.Data.Value.FullBytes, &sip); err != nil {
		return nil, err
	}
	if sip.Version != 65536 || !bytes.Equal(sip.UUID, powershellSIPUUID) || sip.A != 0 || sip.B != 0 || sip.C != 0 || sip.D != 0 || sip.E != 0 {
		return nil, fmt.Errorf("unsupported script SIP identity")
	}
	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], indirect.Digest.Value) {
		return nil, fmt.Errorf("script digest mismatch")
	}
	var content asn1.RawValue
	if err := signatureDER(sd.Content.Content.Bytes, &content); err != nil {
		return nil, err
	}
	return verifySignedContent(sd, spcIndirectOID, content.Bytes)
}

func scriptSignatureBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	format := "powershell"
	if err := starlark.UnpackArgs("script_signature", args, kwargs, "file", &value, "format?", &format); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 16<<20)
	if err != nil {
		return nil, err
	}
	result, err := verifyScriptIntegrity(data, format)
	if err != nil {
		return nil, fmt.Errorf("script_signature: %w", err)
	}
	return signatureIntegrityRecord(result, "script_signature")
}
