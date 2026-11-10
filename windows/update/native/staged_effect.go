package native

import (
	"github.com/tinyrange/trex/windows/uup"
	"strings"
	"sync"
)

// Deferred files outlive the large, short-lived planning graph. Group their
// small owned strings and pointed-to identities in bounded slabs so individual
// readers do not pin scattered allocator spans from that graph. Returned
// values do not retain the store or its temporary interning map.
type stagedEffectStore struct {
	mu          sync.Mutex
	text        strings.Builder
	names       map[string]string
	descriptors []uup.ContentDescriptor
	sha256s     [][32]byte
	sha1s       [][20]byte
	effects     []uup.StageFileEffect
	readers     []stagedReaderRecord
	readerNext  int
}

func (s *stagedEffectStore) ownString(value string) string {
	if value == "" {
		return ""
	}
	if owned, ok := s.names[value]; ok {
		return owned
	}
	if s.names == nil {
		s.names = make(map[string]string)
	}
	if s.text.Cap()-s.text.Len() < len(value) {
		s.text = strings.Builder{}
		s.text.Grow(max(64<<10, len(value)))
	}
	start := s.text.Len()
	s.text.WriteString(value)
	owned := s.text.String()[start:]
	s.names[value] = owned
	return owned
}
func (s *stagedEffectStore) own(effect uup.StageFileEffect) uup.StageFileEffect {
	s.mu.Lock()
	defer s.mu.Unlock()
	effect.Architecture = s.ownString(effect.Architecture)
	effect.CSIFileKey = s.ownString(effect.CSIFileKey)
	effect.Kind = s.ownString(effect.Kind)
	effect.SourceName = s.ownString(effect.SourceName)
	effect.SourceMode = s.ownString(effect.SourceMode)
	effect.StorePath = s.ownString(effect.StorePath)
	effect.Destinations = nil
	if effect.SourceDescriptor != nil {
		if len(s.descriptors) == cap(s.descriptors) {
			s.descriptors = make([]uup.ContentDescriptor, 0, 128)
		}
		s.descriptors = append(s.descriptors, *effect.SourceDescriptor)
		descriptor := &s.descriptors[len(s.descriptors)-1]
		descriptor.Name = s.ownString(descriptor.Name)
		effect.SourceDescriptor = descriptor
	}
	if effect.ExpectedSHA256 != nil {
		if len(s.sha256s) == cap(s.sha256s) {
			s.sha256s = make([][32]byte, 0, 256)
		}
		s.sha256s = append(s.sha256s, *effect.ExpectedSHA256)
		effect.ExpectedSHA256 = &s.sha256s[len(s.sha256s)-1]
	}
	if effect.ExpectedSHA1 != nil {
		if len(s.sha1s) == cap(s.sha1s) {
			s.sha1s = make([][20]byte, 0, 256)
		}
		s.sha1s = append(s.sha1s, *effect.ExpectedSHA1)
		effect.ExpectedSHA1 = &s.sha1s[len(s.sha1s)-1]
	}
	return effect
}
