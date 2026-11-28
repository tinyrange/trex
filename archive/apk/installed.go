package apk

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/tinyrange/trex/filesystem/unixfs"
)

// InstalledPackage describes the APKINDEX fields and the installed payload of
// one Alpine v2 package. Modified package files should retain their original
// payload readers so apk audit can detect the modifications.
type InstalledPackage struct {
	Fields  map[string]string
	Payload []unixfs.Entry
}

// WriteInstalled writes Alpine's v2 installed database records, including file
// ownership and digests. It does not resolve dependencies or run APK scripts.
func WriteInstalled(w io.Writer, packages []InstalledPackage) error {
	packages = slices.Clone(packages)
	slices.SortFunc(packages, func(a, b InstalledPackage) int {
		return strings.Compare(a.Fields["P"], b.Fields["P"])
	})
	var output bytes.Buffer
	names := map[string]bool{}
	for _, pkg := range packages {
		name := pkg.Fields["P"]
		if names[name] || !ValidIdentity(name) || !ValidIdentity(pkg.Fields["V"]) || !ValidIdentity(pkg.Fields["A"]) {
			return fmt.Errorf("apk installed database: invalid or duplicate package %q", name)
		}
		names[name] = true
		checksum := pkg.Fields["C"]
		identity, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(checksum, "Q1"))
		if !strings.HasPrefix(checksum, "Q1") || err != nil || len(identity) != sha1.Size {
			return fmt.Errorf("apk installed database: invalid package checksum for %s", name)
		}
		for _, key := range strings.Split("C P V A S I T U L o m t c D p i k r q s", " ") {
			if value, ok := pkg.Fields[key]; ok {
				if strings.ContainsAny(value, "\r\n\x00") {
					return fmt.Errorf("apk installed database: invalid %s field for %s", key, name)
				}
				fmt.Fprintf(&output, "%s:%s\n", key, value)
			}
		}
		if err := writeOwnedFiles(&output, pkg.Payload); err != nil {
			return fmt.Errorf("apk installed database: %s: %w", name, err)
		}
		output.WriteByte('\n')
	}
	_, err := output.WriteTo(w)
	return err
}

func writeOwnedFiles(output *bytes.Buffer, payload []unixfs.Entry) error {
	entries, err := unixfs.Normalize(payload)
	if err != nil {
		return err
	}
	byPath := make(map[string]unixfs.Entry, len(entries))
	owned := make(map[string][]unixfs.Entry)
	for _, e := range entries {
		if strings.ContainsAny(e.Path, "\r\n") {
			return fmt.Errorf("invalid path %q", e.Path)
		}
		byPath[e.Path] = e
		if e.Mode&0170000 == unixfs.Directory {
			owned[e.Path] = nil
		}
	}
	digests := map[string]string{}
	for _, e := range entries {
		if e.Mode&0170000 != unixfs.Directory {
			dir := path.Dir(e.Path)
			owned[dir] = append(owned[dir], e)
		}
	}
	for _, dir := range entries {
		if dir.Mode&0170000 != unixfs.Directory || (dir.Path == "." && len(owned[dir.Path]) == 0) {
			continue
		}
		name := dir.Path
		if name == "." {
			name = ""
		}
		fmt.Fprintf(output, "F:%s\n", name)
		writeACL(output, 'M', dir, 0755)
		for _, e := range owned[dir.Path] {
			fmt.Fprintf(output, "R:%s\n", path.Base(e.Path))
			writeACL(output, 'a', e, 0644)
			digestSource := e
			if e.Hardlink {
				digestSource = byPath[e.Target]
			}
			checksum, ok := digests[digestSource.Path]
			if !ok {
				checksum, err = installedDigest(digestSource)
				if err != nil {
					return fmt.Errorf("%s: %w", e.Path, err)
				}
				digests[digestSource.Path] = checksum
			}
			if checksum != "" {
				fmt.Fprintf(output, "Z:%s\n", checksum)
			}
		}
	}
	return nil
}

func writeACL(w *bytes.Buffer, field byte, e unixfs.Entry, defaultMode uint32) {
	mode := e.Mode & 07777
	if e.UID != 0 || e.GID != 0 || mode != defaultMode {
		fmt.Fprintf(w, "%c:%d:%d:%o\n", field, e.UID, e.GID, mode)
	}
}

func installedDigest(e unixfs.Entry) (string, error) {
	hash := sha1.New()
	switch e.Mode & 0170000 {
	case unixfs.Regular:
		if _, err := io.Copy(hash, io.NewSectionReader(e.Data, 0, e.Data.Size())); err != nil {
			return "", err
		}
	case unixfs.Symlink:
		fmt.Fprint(hash, e.Target)
	default:
		return "", nil
	}
	return "Q1" + base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}
