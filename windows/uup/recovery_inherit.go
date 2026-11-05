package uup

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/windows/msdelta"
)

// InheritedRecovery binds immutable record bytes to their base-image path.
type InheritedRecovery struct {
	Data       []byte
	SourcePath string
}

// InheritedPlannedRecovery retains a base-image sidecar for unchanged content.
// Absence is not permission to omit recovery for other source modes. Generated
// forward payload recovery and servicing timestamp policy are separate.
func (s *CumulativeStage) InheritedPlannedRecovery(effect StageFileEffect) (*InheritedRecovery, error) {
	if s == nil || effect.Kind != "component-file" || effect.SourceMode != "predecessor" {
		return nil, nil
	}
	d := effect.SourceDescriptor
	if d == nil || effect.ExpectedSHA256 == nil || d.SHA256 != *effect.ExpectedSHA256 {
		return nil, fmt.Errorf("inherited recovery requires a verified predecessor identity")
	}
	if s.baseRecovery == nil {
		return nil, nil
	}
	return s.baseRecovery.inherited(*d)
}

func (r *reverseAssemblyResolver) inherited(d ContentDescriptor) (*InheritedRecovery, error) {
	if r == nil || r.base == nil {
		return nil, nil
	}
	if d.Length < 0 {
		return nil, fmt.Errorf("inherited recovery source exceeds bound")
	}
	id, relative, err := ParseComponentContentName(d.Name)
	if err != nil {
		return nil, err
	}
	if _, err := baseAssemblyContentPath(r.imagePath, d.Name); err != nil {
		return nil, err
	}
	relative = strings.ReplaceAll(relative, `\`, "/")
	r.indexFamilies()
	if r.err != nil {
		return nil, r.err
	}
	var selected *InheritedRecovery
	var selectedTarget []byte
	for _, stem := range r.families[id.FamilyKey()] {
		root := r.imagePath + "/Windows/WinSxS/" + stem + "/"
		reverse, err := r.base.OpenFile(root + "r/" + relative)
		if err != nil {
			continue
		}
		if d.Length > defaultMaximumDeltaRecord {
			return nil, fmt.Errorf("inherited recovery source exceeds bound")
		}
		stored, err := r.base.OpenFile(root + relative)
		if err != nil {
			continue
		}
		source, err := expandAssemblyBasis(stored)
		if err != nil {
			return nil, err
		}
		if source.Size() != d.Length {
			continue
		}
		// Bind the base file before accepting a neighboring recovery record.
		data := make([]byte, d.Length)
		if _, err = io.ReadFull(io.NewSectionReader(source, 0, source.Size()), data); err != nil {
			return nil, err
		}
		if verifyContentDescriptor(d, data) != nil {
			continue
		}
		if reverse.Size() < 0 || reverse.Size() > defaultMaximumDeltaRecord {
			return nil, fmt.Errorf("inherited recovery record exceeds bound")
		}
		record := make([]byte, reverse.Size())
		if _, err = io.ReadFull(io.NewSectionReader(reverse, 0, reverse.Size()), record); err != nil {
			return nil, err
		}
		h, err := msdelta.ParsePSFRecord(record)
		if err != nil {
			return nil, err
		}
		if h.Version != "PA31" || h.FileTypeSet&0x100 == 0 || h.HashAlgorithm != 0x800c || !equalHashBytes(d.SHA256, h.ExtensionHash) {
			return nil, fmt.Errorf("inherited recovery is not bound to installed content")
		}
		target, err := msdelta.ApplyPSFRecordBounded(data, record, uint64(defaultMaximumDeltaRecord))
		if err != nil {
			return nil, err
		}
		if selected != nil && !bytes.Equal(selectedTarget, target) {
			return nil, fmt.Errorf("ambiguous inherited recovery target")
		}
		if selected == nil {
			selected, selectedTarget = &InheritedRecovery{Data: record, SourcePath: strings.TrimPrefix(root+"r/"+relative, r.imagePath)}, target
		}
	}
	return selected, nil
}
