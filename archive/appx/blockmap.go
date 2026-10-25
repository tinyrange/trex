package appx

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const blockMapNamespace = "http://schemas.microsoft.com/appx/2010/blockmap"
const blockSize = 65536

// VerifyBlockMap checks decoded SHA256 blocks and complete payload coverage.
// This is integrity against an UNAUTHENTICATED map, not publisher authentication.
// Bundle members must be verified separately. maximum bounds total decoded bytes.
// ZIP compressed-block sizes and signature digests are not authenticated here.
func (a *Archive) VerifyBlockMap(maximum uint64) error {
	f := a.zipFiles["appxblockmap.xml"]
	if f == nil || f.UncompressedSize64 > maxManifest {
		return fmt.Errorf("appx: missing or oversized block map")
	}
	r, err := f.Open()
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxManifest+1))
	_ = r.Close()
	if err != nil {
		return err
	}
	var doc struct {
		XMLName xml.Name
		Method  string `xml:"HashMethod,attr"`
		Files   []struct {
			Name   string  `xml:"Name,attr"`
			Size   *uint64 `xml:"Size,attr"`
			Blocks []struct {
				Hash string `xml:"Hash,attr"`
			} `xml:"Block"`
		} `xml:"File"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("appx: block map: %w", err)
	}
	if doc.XMLName != (xml.Name{Space: blockMapNamespace, Local: "BlockMap"}) || doc.Method != "http://www.w3.org/2001/04/xmlenc#sha256" || len(doc.Files) == 0 {
		return fmt.Errorf("appx: unsupported or empty block map")
	}
	exempt := map[string]bool{"appxblockmap.xml": true, "appxsignature.p7x": true, "[content_types].xml": true, "appxmetadata/codeintegrity.cat": true}
	if a.Kind == "bundle" {
		if len(doc.Files) != 1 {
			return fmt.Errorf("appx: bundle map must contain only its manifest")
		}
		for _, m := range a.Packages {
			exempt[strings.ToLower(m.Name)] = true
		}
	}
	seen := map[string]bool{}
	var total uint64
	buf := make([]byte, blockSize)
	for _, file := range doc.Files {
		name := strings.ReplaceAll(file.Name, `\`, "/")
		key := strings.ToLower(name)
		entry := a.zipFiles[key]
		if !safeName(name) || seen[key] || exempt[key] || entry == nil || entry.FileInfo().IsDir() || file.Size == nil || *file.Size != entry.UncompressedSize64 {
			return fmt.Errorf("appx: invalid block map file %q", name)
		}
		if a.Kind == "bundle" && key != "appxmetadata/appxbundlemanifest.xml" {
			return fmt.Errorf("appx: invalid bundle block map")
		}
		seen[key] = true
		size := *file.Size
		if size > maximum-total {
			return fmt.Errorf("appx: block map decoded budget exceeded")
		}
		total += size
		if uint64(len(file.Blocks)) != (size+blockSize-1)/blockSize {
			return fmt.Errorf("appx: invalid block count for %q", name)
		}
		stream, err := entry.Open()
		if err != nil {
			return err
		}
		verifyErr := func() error {
			defer stream.Close()
			remaining := size
			for i, b := range file.Blocks {
				want, err := base64.StdEncoding.Strict().DecodeString(b.Hash)
				if err != nil || len(want) != sha256.Size {
					return fmt.Errorf("appx: invalid block hash for %q", name)
				}
				n := min(remaining, uint64(blockSize))
				if _, err := io.ReadFull(stream, buf[:n]); err != nil {
					return fmt.Errorf("appx: %s block %d: %w", name, i, err)
				}
				got := sha256.Sum256(buf[:n])
				if !bytes.Equal(want, got[:]) {
					return fmt.Errorf("appx: block hash mismatch for %q block %d", name, i)
				}
				remaining -= n
			}
			// Force the ZIP reader through EOF, including CRC verification for empty files.
			n, err := stream.Read(buf[:1])
			if n != 0 || err != io.EOF {
				return fmt.Errorf("appx: invalid payload ending for %q: %v", name, err)
			}
			return nil
		}()
		if verifyErr != nil {
			return verifyErr
		}
	}
	for key, f := range a.zipFiles {
		if !f.FileInfo().IsDir() && !seen[key] && !exempt[key] {
			return fmt.Errorf("appx: payload %q missing from block map", key)
		}
	}
	return nil
}
