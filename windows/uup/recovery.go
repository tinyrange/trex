package uup

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/windows/msdelta"
)

// PlannedRecoveryFile finds the exact r/ sidecar of an admitted component file
// in the PSF index. These records are intentionally not ordinary forward graph
// targets. Absence here is distinct from failure to decode a present record.
func (s *CumulativeStage) PlannedRecoveryFile(effect StageFileEffect) (*CIXFile, error) {
	if s == nil || s.Index == nil || effect.Kind != "component-file" {
		return nil, nil
	}
	identity, relative, err := ParseComponentContentName(effect.SourceName)
	if err != nil {
		return nil, fmt.Errorf("recovery component source: %w", err)
	}
	name := normalizeCIXName(identity.Stem + `\r\` + strings.ReplaceAll(relative, "/", `\`))
	var found *CIXFile
	for _, file := range s.Index.Files {
		if normalizeCIXName(file.Name) != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ambiguous recovery record %q", name)
		}
		copy := file
		found = &copy
	}
	return found, nil
}

// CreatePlannedRecovery creates an experimental reverse record for one admitted
// forward payload. It does not select recovery files or change CSI storage flags.
// File time is explicit until the servicing timestamp policy is established.
func (s *CumulativeStage) CreatePlannedRecovery(effect StageFileEffect, fileTime uint64) ([]byte, error) {
	if s == nil || effect.Kind != "component-file" || effect.SourceMode != "payload" {
		return nil, fmt.Errorf("recovery requires a planned component payload")
	}
	payload, ok := s.expressByTarget[normalizeCIXName(effect.SourceName)]
	if !ok || payload.Literal || payload.Basis == nil {
		return nil, fmt.Errorf("recovery requires a hash-qualified forward basis for %q", effect.SourceName)
	}
	if effect.ExpectedSHA256 == nil || *effect.ExpectedSHA256 != payload.Target.SHA256 {
		return nil, fmt.Errorf("recovery target differs from planned content identity")
	}
	const maximum = 128 << 20
	if payload.Target.Length < 0 || payload.Target.Length > maximum || payload.Basis.Length < 0 || payload.Basis.Length > maximum {
		return nil, fmt.Errorf("recovery input exceeds bound")
	}
	basis, err := s.resolveExpressBasis(s.nameExpressBasis(payload.Target.Name, payload.Basis))
	if err != nil {
		return nil, fmt.Errorf("recovery basis: %w", err)
	}
	installed, err := s.materializeExpress(payload)
	if err != nil {
		return nil, err
	}
	record, err := msdelta.CreateReversePSFRecord(installed, basis, fileTime, maximum)
	if err != nil {
		return nil, err
	}
	recovered, err := msdelta.ApplyPSFRecordBounded(installed, record, maximum)
	if err != nil {
		return nil, fmt.Errorf("recovery round trip: %w", err)
	}
	if !bytes.Equal(recovered, basis) {
		return nil, fmt.Errorf("recovery round trip differs from admitted basis")
	}
	return record, nil
}

// PlannedRecoveryBasis reports the exact forward basis without decoding payloads.
// A nil result means no supported explicit basis, not proof that no recovery
// sidecar is required. Callers must not use it as an applicability decision.
func (s *CumulativeStage) PlannedRecoveryBasis(effect StageFileEffect) (*ContentDescriptor, error) {
	if s == nil || effect.Kind != "component-file" || effect.SourceMode != "payload" {
		return nil, nil
	}
	p, ok := s.expressByTarget[normalizeCIXName(effect.SourceName)]
	if !ok || p.Literal || p.Basis == nil {
		return nil, nil
	}
	if effect.ExpectedSHA256 == nil || *effect.ExpectedSHA256 != p.Target.SHA256 {
		return nil, fmt.Errorf("recovery target differs from planned content identity")
	}
	copy := *s.nameExpressBasis(p.Target.Name, p.Basis)
	return &copy, nil
}
