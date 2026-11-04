package uup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/msdelta"
)

// reverseAssemblyResolver uses the installed component's r/ payload to recover
// a pruned checkpoint, or finds unchanged bytes in a newer installed component.
// This is content recovery, never package applicability.
// Family and relative path select candidates; declared size and SHA-256 select
// the target, and both the delta's source and target hashes remain enforced.
type reverseAssemblyResolver struct {
	base      assemblyArchive
	imagePath string
	once      sync.Once
	families  map[string][]string
	err       error
}

func (r *reverseAssemblyResolver) resolve(d ContentDescriptor) (storage.Reader, bool, error) {
	if r == nil || r.base == nil || d.Name == "" {
		return nil, false, nil
	}
	identity, relative, err := ParseComponentContentName(d.Name)
	if err != nil {
		return nil, false, nil
	}
	relative = strings.ReplaceAll(relative, `\`, "/")
	// Use the ordinary content-path validator before inserting an r/ segment.
	if _, err := baseAssemblyContentPath(r.imagePath, d.Name); err != nil {
		return nil, false, err
	}
	r.indexFamilies()
	if r.err != nil {
		return nil, false, r.err
	}
	// A component version may advance without changing this file. Prefer its
	// exact content identity before attempting to replay historical updates.
	for _, stem := range r.families[identity.FamilyKey()] {
		stored, err := r.base.OpenFile(r.imagePath + "/Windows/WinSxS/" + stem + "/" + relative)
		if err != nil {
			continue
		}
		file, err := expandAssemblyBasis(stored)
		if err != nil {
			return nil, false, err
		}
		if file.Size() != d.Length {
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(file, 0, file.Size())); err != nil {
			return nil, false, err
		}
		if equalHashBytes(d.SHA256, h.Sum(nil)) {
			return file, true, nil
		}
	}
	for _, stem := range r.families[identity.FamilyKey()] {
		root := r.imagePath + "/Windows/WinSxS/" + stem + "/"
		reverse, err := r.base.OpenFile(root + "r/" + relative)
		if err != nil {
			continue
		}
		if reverse.Size() < 0 || reverse.Size() > defaultMaximumDeltaRecord {
			return nil, false, fmt.Errorf("reverse basis %q exceeds delta bound", d.Name)
		}
		// Sizes are already bounded. Allocate once instead of growing and
		// copying multi-megabyte reverse records through io.ReadAll.
		delta := make([]byte, int(reverse.Size()))
		if _, err := io.ReadFull(io.NewSectionReader(reverse, 0, reverse.Size()), delta); err != nil {
			return nil, false, err
		}
		header, err := msdelta.ParsePSFRecord(delta)
		if err != nil {
			return nil, false, fmt.Errorf("reverse basis %q: %w", root+relative, err)
		}
		if header.TargetSize != uint64(d.Length) || header.HashAlgorithm != 0x800c || !equalHashBytes(d.SHA256, header.TargetHash) {
			continue
		}
		if d.Length < 0 || d.Length > maximumCanonicalTarget {
			return nil, false, fmt.Errorf("reverse basis target exceeds bound")
		}
		stored, err := r.base.OpenFile(root + relative)
		if err != nil {
			return nil, false, err
		}
		source, err := expandAssemblyBasis(stored)
		if err != nil {
			return nil, false, err
		}
		if source.Size() < 0 || source.Size() > maximumCanonicalTarget {
			return nil, false, fmt.Errorf("reverse basis source exceeds bound")
		}
		data := make([]byte, int(source.Size()))
		if _, err := io.ReadFull(io.NewSectionReader(source, 0, source.Size()), data); err != nil {
			return nil, false, err
		}
		target, err := msdelta.ApplyPSFRecordBounded(data, delta, uint64(d.Length))
		if err != nil {
			return nil, false, fmt.Errorf("reverse basis %q: %w", root+relative, err)
		}
		if int64(len(target)) != d.Length || sha256.Sum256(target) != d.SHA256 {
			return nil, false, fmt.Errorf("reverse basis content identity mismatch")
		}
		return &starfile.Bytes{Name: d.Name, Data: target}, true, nil
	}
	return nil, false, nil
}

func (r *reverseAssemblyResolver) indexFamilies() {
	r.once.Do(func() {
		r.families = make(map[string][]string)
		entries, err := r.base.List(r.imagePath + "/Windows/WinSxS")
		if err != nil {
			r.err = err
			return
		}
		for _, entry := range entries {
			if !entry.Directory {
				continue
			}
			id, err := parseComponentStem(entry.Name)
			if err == nil {
				r.families[id.FamilyKey()] = append(r.families[id.FamilyKey()], entry.Name)
			}
		}
	})
}
