package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"strings"
	"testing"
)

func TestScriptSignatureIntegrityAndEncoding(t *testing.T) {
	identity := signingTestIdentity(t)
	for _, format := range []string{"powershell", "xml"} {
		for _, wide := range []bool{false, true} {
			body := "\ufeff# signed non-ASCII: café 🙂\r\n"
			digest := sha256.Sum256(scriptUTF16(body))
			sip, err := asn1.Marshal(appxSIPInfo{Version: 65536, UUID: powershellSIPUUID})
			if err != nil {
				t.Fatal(err)
			}
			indirect := signingSequence(signingSequence(signingOID(appxSIPOID), sip), signingSequence(signingAlgorithm(sha256OID), signingTLV(4, digest[:])))
			signature, err := signPKCS7Content(indirect, spcIndirectOID, identity)
			if err != nil {
				t.Fatal(err)
			}
			open, close := "# ", ""
			if format == "xml" {
				open, close = "<!-- ", " -->"
			}
			var block strings.Builder
			block.WriteString(body + "\r\n" + open + "SIG # Begin signature block" + close + "\r\n")
			encoded := base64.StdEncoding.EncodeToString(signature)
			for len(encoded) > 0 {
				n := min(64, len(encoded))
				block.WriteString(open + encoded[:n] + close + "\r\n")
				encoded = encoded[n:]
			}
			block.WriteString(open + "SIG # End signature block" + close + "\r\n")
			encode := func(text string) []byte {
				if wide {
					return scriptUTF16(text)
				}
				return []byte(text)
			}
			valid := encode(block.String())
			got, err := verifyScriptIntegrity(valid, format)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.signer.Raw, identity.certificate.Raw) {
				t.Fatal("wrong signer")
			}
			for _, invalid := range []string{
				strings.Replace(block.String(), "café", "cafe", 1),
				strings.Replace(block.String(), "\r\n", "\n", 1),
				block.String() + "# unsigned code\r\n",
				block.String() + open + "SIG # Begin signature block" + close + "\r\n",
				strings.Replace(block.String(), "SIG # End signature block", "missing end", 1),
			} {
				if _, err := verifyScriptIntegrity(encode(invalid), format); err == nil {
					t.Fatal("malformed or modified script accepted")
				}
			}
			if wide {
				if _, err := verifyScriptIntegrity(valid[:len(valid)-1], format); err == nil {
					t.Fatal("odd UTF-16 accepted")
				}
			}
		}
	}
	if _, _, err := scriptSignatureParts([]byte{0xff}, "powershell"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
