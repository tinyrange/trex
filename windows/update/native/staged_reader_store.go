package native

import (
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"github.com/tinyrange/trex/windows/uup"
)

type stagedReaderRecord struct {
	reader reopenedStageReader
	digest [32]byte
}

func (s *stagedEffectStore) ownPointer(effect uup.StageFileEffect) *uup.StageFileEffect {
	owned := s.own(effect)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.effects) == cap(s.effects) {
		s.effects = make([]uup.StageFileEffect, 0, 128)
	}
	s.effects = append(s.effects, owned)
	return &s.effects[len(s.effects)-1]
}

// A returned reader owns its immutable opener and one slab, never the store.
// Slots are never recycled: readers may survive their original staging plan.
func (s *stagedEffectStore) newReader(size int64, cache *stageContentCache, key bytecache.Key, open func() (storage.Reader, error), digest [32]byte, known bool) *reopenedStageReader {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.readers) == 0 {
		s.readers = make([]stagedReaderRecord, 128)
		s.readerNext = 0
	}
	// readers is a fixed-length slab so records containing atomics are never
	// copied by slice growth after publication.
	if s.readerNext == len(s.readers) {
		s.readers = make([]stagedReaderRecord, 128)
		s.readerNext = 0
	}
	record := &s.readers[s.readerNext]
	s.readerNext++
	r := &record.reader
	r.size = size
	r.compressed = cache
	r.key = key
	r.open = open
	if known {
		record.digest = digest
		r.expectedSHA256 = &record.digest
	}
	return r
}
