package uup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/msdelta"
)

const (
	// Precompressed Defender definitions can carry nearly literal PA31
	// records (mpasbase.vdm:133705296 bytes). Permit records up to the same
	// 128MiB bound independently of decoded target sizes and reuse caches.
	defaultMaximumDeltaRecord = int64(128 << 20)
	// Current WebView msedge.dll targets reach331654472 bytes. This bounds
	// one reconstructed file, not how much the decoded cache retains.
	maximumCanonicalTarget    = int64(512 << 20)
	maximumCanonicalContainer = int64(512 << 20)
	// Each completed stage remains a predecessor for subsequent stages. Its
	// decoded reuse cache is additional to the caller's retained image files,
	// so do not reserve another full cabinet's worth of decoded targets per
	// stage. Eviction changes reuse only, never the supported content extent.
	maximumCanonicalRetainedTarget = int64(128 << 20)
)

type CumulativeStage struct {
	MetadataName          string
	PSFName               string
	Metadata              *wim.Archive
	metadataCAB           *cab.Archive
	PSF                   storage.Reader
	Index                 *ContainerIndex
	History               *ContainerIndex
	Graph                 *CumulativeGraph
	canonicalByTarget     map[string]DeltaPayload
	expressByTarget       map[string]DeltaPayload
	canonicalCache        map[string][]byte
	canonicalRetained     int64
	canonicalMu           sync.Mutex
	carryIndexOnce        sync.Once
	carryByTarget         map[string]CarryPayload
	metadataArchives      []stageMetadataArchive
	assemblyResolver      func(ContentDescriptor) (storage.Reader, error)
	assemblyNameResolver  func(string) (storage.Reader, error)
	assemblyReadOrder     func(ContentDescriptor) (wim.FileReadOrder, bool)
	assemblyNameReadOrder func(string) (wim.FileReadOrder, bool)
	assemblyDictionary    func() (storage.Reader, error)
	predecessorByStem     map[string]string
}

type stageMetadataArchive struct {
	name string
	wim  *wim.Archive
	cab  *cab.Archive
}

// StageMetadataCache is one portable, bounded decompressed-chunk cache shared
// by all WIM metadata payloads in a servicing sequence.
type StageMetadataCache struct {
	store *bytecache.Cache
	next  atomic.Uint64
}

func NewStageMetadataCache(maximumBytes int64) (*StageMetadataCache, error) {
	if maximumBytes < 0 {
		return nil, fmt.Errorf("uup servicing: negative metadata cache bound %d", maximumBytes)
	}
	return &StageMetadataCache{store: bytecache.New(maximumBytes)}, nil
}

type stageMetadataEntry struct {
	Name string
	Path string
}

type stageReadOrder struct {
	archive int
	wim     wim.FileReadOrder
	name    string
}

func (s *CumulativeStage) metadataReadOrder(name string) stageReadOrder {
	for index, archive := range s.metadataArchives {
		if archive.wim != nil {
			order, err := archive.wim.ReadOrder(name)
			if err != nil && !strings.HasPrefix(strings.ToLower(strings.TrimPrefix(name, "/")), "image") {
				order, err = archive.wim.ReadOrder("/image1/" + strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/"))
			}
			if err == nil {
				return stageReadOrder{archive: index, wim: order, name: strings.ToLower(name)}
			}
		}
		if archive.cab != nil {
			if _, err := archive.cab.Lookup(name); err == nil {
				return stageReadOrder{archive: index, name: strings.ToLower(name)}
			}
		}
	}
	return stageReadOrder{archive: len(s.metadataArchives), name: strings.ToLower(name)}
}

func (s *CumulativeStage) metadataEntries() ([]stageMetadataEntry, error) {
	if s == nil {
		return nil, fmt.Errorf("uup servicing: stage is required")
	}
	if len(s.metadataArchives) != 0 {
		var result []stageMetadataEntry
		for _, archive := range s.metadataArchives {
			if archive.wim != nil {
				if err := archive.wim.Walk("/image1", func(entry wim.EntryInfo) error {
					if !entry.Directory {
						result = append(result, stageMetadataEntry{Name: entry.Name, Path: entry.Path})
					}
					return nil
				}); err != nil {
					return nil, fmt.Errorf("uup servicing: enumerate metadata %q: %w", archive.name, err)
				}
			}
			if archive.cab != nil {
				for _, file := range archive.cab.Files() {
					result = append(result, stageMetadataEntry{Name: path.Base(strings.ReplaceAll(file.Name, "\\", "/")), Path: file.Name})
				}
			}
		}
		return result, nil
	}
	if s.Metadata != nil {
		var result []stageMetadataEntry
		if err := s.Metadata.Walk("/image1", func(entry wim.EntryInfo) error {
			if !entry.Directory {
				result = append(result, stageMetadataEntry{Name: entry.Name, Path: entry.Path})
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return result, nil
	}
	if s.metadataCAB != nil {
		files := s.metadataCAB.Files()
		result := make([]stageMetadataEntry, 0, len(files))
		for _, file := range files {
			result = append(result, stageMetadataEntry{Name: path.Base(strings.ReplaceAll(file.Name, "\\", "/")), Path: file.Name})
		}
		return result, nil
	}
	return nil, fmt.Errorf("uup servicing: stage metadata is required")
}

// assemblyEntries returns both stored metadata members and logical manifest
// targets represented only by the stage's content graph. Express WIMs may omit
// a physical placeholder for a MUM or component manifest whose complete bytes
// are reconstructed from the PSF.
func (s *CumulativeStage) assemblyEntries() ([]stageMetadataEntry, error) {
	entries, err := s.metadataEntries()
	if err != nil {
		return nil, err
	}
	if s.Graph == nil {
		return entries, nil
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		seen[assemblyEntryKey(entry.Path)] = struct{}{}
	}
	for _, payload := range s.Graph.Payloads {
		name := strings.ReplaceAll(payload.Target.Name, "\\", "/")
		switch strings.ToLower(path.Ext(name)) {
		case ".mum", ".manifest":
		default:
			continue
		}
		key := assemblyEntryKey(name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, stageMetadataEntry{Name: path.Base(name), Path: payload.Target.Name})
	}
	return entries, nil
}

func assemblyEntryKey(name string) string {
	name = strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/")
	if strings.HasPrefix(strings.ToLower(name), "image1/") {
		name = name[len("image1/"):]
	}
	return strings.ToLower(name)
}

func (s *CumulativeStage) openMetadataFile(name string) (storage.Reader, error) {
	if len(s.metadataArchives) != 0 {
		var found storage.Reader
		var foundIn string
		for _, archive := range s.metadataArchives {
			var file storage.Reader
			var err error
			if archive.wim != nil {
				file, err = archive.wim.OpenFile(name)
				if err != nil && !strings.HasPrefix(strings.ToLower(strings.TrimPrefix(name, "/")), "image") {
					file, err = archive.wim.OpenFile("/image1/" + strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/"))
				}
			} else if archive.cab != nil {
				file, err = archive.cab.Lookup(name)
			}
			if err != nil {
				continue
			}
			if found != nil {
				return nil, fmt.Errorf("uup servicing: metadata member %q is ambiguous across %q and %q", name, foundIn, archive.name)
			}
			found, foundIn = file, archive.name
		}
		if found == nil {
			return nil, fmt.Errorf("uup servicing: metadata member %q is unavailable", name)
		}
		return found, nil
	}
	if s.Metadata != nil {
		file, err := s.Metadata.OpenFile(name)
		if err == nil || strings.HasPrefix(strings.ToLower(strings.TrimPrefix(name, "/")), "image") {
			return file, err
		}
		return s.Metadata.OpenFile("/image1/" + strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/"))
	}
	if s.metadataCAB != nil {
		return s.metadataCAB.Lookup(name)
	}
	return nil, fmt.Errorf("uup servicing: stage metadata is required")
}

func (s *CumulativeStage) openAssemblyFile(name string) (storage.Reader, error) {
	if s != nil && len(s.expressByTarget) != 0 {
		candidates := []string{name}
		normalized := strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/")
		if strings.HasPrefix(strings.ToLower(normalized), "image1/") {
			candidates = append(candidates, normalized[len("image1/"):])
		}
		candidates = append(candidates, path.Base(normalized))
		var found *DeltaPayload
		for _, candidate := range candidates {
			if payload, exists := s.expressByTarget[normalizeCIXName(candidate)]; exists {
				copy := payload
				if found != nil && normalizeCIXName(found.Target.Name) != normalizeCIXName(copy.Target.Name) {
					return nil, fmt.Errorf("uup servicing: assembly target %q is ambiguous", name)
				}
				found = &copy
			}
		}
		if found != nil {
			data, err := s.materializeExpress(*found)
			if err != nil {
				return nil, err
			}
			return &starvalue.Bytes{Name: found.Target.Name, Data: data}, nil
		}
	}
	file, err := s.openMetadataFile(name)
	if err != nil {
		return nil, err
	}
	if file.Size() < 4 {
		return file, nil
	}
	var signature [4]byte
	if _, err := file.ReadAt(signature[:], 0); err != nil {
		return nil, fmt.Errorf("uup servicing: read assembly header %q: %w", name, err)
	}
	if signature != [4]byte{'D', 'C', 'M', 1} {
		return file, nil
	}
	return s.materializeDeltaCompressedManifest(name, file)
}

func (s *CumulativeStage) materializeDeltaCompressedManifest(name string, file storage.Reader) (storage.Reader, error) {
	key := "dcm\x00" + normalizeCIXName(name)
	s.canonicalMu.Lock()
	if cached := s.canonicalCache[key]; cached != nil {
		s.canonicalMu.Unlock()
		return &starvalue.Bytes{Name: name, Data: cached}, nil
	}
	s.canonicalMu.Unlock()
	if file.Size() < 16 || file.Size() > defaultMaximumDeltaRecord {
		return nil, fmt.Errorf("uup servicing: delta-compressed manifest %q has invalid size %d", name, file.Size())
	}
	record := make([]byte, file.Size()-4)
	if _, err := io.ReadFull(io.NewSectionReader(file, 4, int64(len(record))), record); err != nil {
		return nil, fmt.Errorf("uup servicing: read delta-compressed manifest %q: %w", name, err)
	}
	header, err := msdelta.Parse(record)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: parse delta-compressed manifest %q: %w", name, err)
	}
	if header.TargetSize > uint64(maximumAssemblyManifestSize) {
		return nil, fmt.Errorf("uup servicing: delta-compressed manifest %q target size %d exceeds %d-byte bound", name, header.TargetSize, maximumAssemblyManifestSize)
	}
	if s.assemblyDictionary == nil {
		return nil, fmt.Errorf("uup servicing: delta-compressed manifest %q has no dictionary resolver", name)
	}
	basisFile, err := s.assemblyDictionary()
	if err != nil {
		return nil, fmt.Errorf("uup servicing: resolve delta-compressed manifest dictionary for %q: %w", name, err)
	}
	if basisFile.Size() < 0 || basisFile.Size() > maximumAssemblyManifestSize {
		return nil, fmt.Errorf("uup servicing: delta-compressed manifest dictionary for %q has invalid size %d", name, basisFile.Size())
	}
	basis := make([]byte, basisFile.Size())
	if _, err := io.ReadFull(io.NewSectionReader(basisFile, 0, basisFile.Size()), basis); err != nil {
		return nil, fmt.Errorf("uup servicing: read delta-compressed manifest dictionary for %q: %w", name, err)
	}
	target, err := msdelta.ApplyBounded(basis, record, uint64(maximumAssemblyManifestSize))
	if err != nil {
		return nil, fmt.Errorf("uup servicing: reconstruct delta-compressed manifest %q from %v (%d bytes): %w", name, basisFile, len(basis), err)
	}
	return &starvalue.Bytes{Name: name, Data: s.retainTarget(key, target, maximumCanonicalRetainedTarget)}, nil
}

// retainTarget caches already verified immutable bytes. The retention bound
// limits reuse, not how many files a stage may reconstruct. Evicting a cache
// reference leaves readers of previously returned byte slices valid.
func (s *CumulativeStage) retainTarget(key string, target []byte, maximumBytes int64) []byte {
	s.canonicalMu.Lock()
	defer s.canonicalMu.Unlock()
	if cached := s.canonicalCache[key]; cached != nil {
		return cached
	}
	if int64(len(target)) > maximumBytes {
		return target
	}
	for oldKey, old := range s.canonicalCache {
		if s.canonicalRetained+int64(len(target)) <= maximumBytes {
			break
		}
		delete(s.canonicalCache, oldKey)
		s.canonicalRetained -= int64(len(old))
	}
	if s.canonicalCache == nil {
		s.canonicalCache = make(map[string][]byte)
	}
	s.canonicalCache[key] = target
	s.canonicalRetained += int64(len(target))
	return target
}

func (s *CumulativeStage) releaseAssemblyFile(name string) {
	key := normalizeCIXName(name)
	keys := []string{key}
	if strings.HasPrefix(key, "image1\\") {
		keys = append(keys, strings.TrimPrefix(key, "image1\\"))
	}
	if separator := strings.LastIndexByte(key, '\\'); separator >= 0 {
		keys = append(keys, key[separator+1:])
	}
	s.canonicalMu.Lock()
	for _, candidate := range keys {
		for _, cacheKey := range []string{candidate, "dcm\x00" + candidate} {
			if data := s.canonicalCache[cacheKey]; data != nil {
				delete(s.canonicalCache, cacheKey)
				s.canonicalRetained -= int64(len(data))
			}
		}
	}
	s.canonicalMu.Unlock()
}

func (s *CumulativeStage) materializeExpress(payload DeltaPayload) ([]byte, error) {
	key := normalizeCIXName(payload.Target.Name)
	s.canonicalMu.Lock()
	if cached := s.canonicalCache[key]; cached != nil {
		s.canonicalMu.Unlock()
		return cached, nil
	}
	s.canonicalMu.Unlock()
	if s.PSF == nil {
		return nil, fmt.Errorf("uup servicing: express target %q has no PSF payload", payload.Target.Name)
	}
	if err := validatePSFRecordRange(payload.RecordOffset, payload.Record.Length, s.PSF.Size()); err != nil {
		return nil, fmt.Errorf("uup servicing: express target %q: %w", payload.Target.Name, err)
	}
	record := make([]byte, payload.Record.Length)
	if _, err := io.ReadFull(io.NewSectionReader(s.PSF, payload.RecordOffset, payload.Record.Length), record); err != nil {
		return nil, fmt.Errorf("uup servicing: read express record for %q: %w", payload.Target.Name, err)
	}
	if err := verifyContentDescriptor(payload.Record, record); err != nil {
		return nil, fmt.Errorf("uup servicing: express record for %q: %w", payload.Target.Name, err)
	}
	if payload.Literal {
		if payload.RecordType != "RAW" || payload.Basis != nil || payload.RecordBasis != nil || payload.RecordTarget != nil {
			return nil, fmt.Errorf("uup servicing: literal target %q has delta reconstruction fields", payload.Target.Name)
		}
		if err := verifyContentDescriptor(payload.Target, record); err != nil {
			return nil, fmt.Errorf("uup servicing: literal target %q: %w", payload.Target.Name, err)
		}
		return s.retainTarget(key, record, maximumCanonicalRetainedTarget), nil
	}
	patch := record
	var err error
	switch payload.RecordType {
	case "RAW":
	case "PA30":
		if payload.RecordTarget == nil {
			return nil, fmt.Errorf("uup servicing: express target %q has no nested record target", payload.Target.Name)
		}
		basis, err := s.resolveExpressBasis(payload.RecordBasis)
		if err != nil {
			return nil, fmt.Errorf("uup servicing: resolve nested record basis for %q: %w", payload.Target.Name, err)
		}
		patch, err = msdelta.ApplyBounded(basis, record, uint64(defaultMaximumDeltaRecord))
		if err != nil {
			return nil, fmt.Errorf("uup servicing: reconstruct nested record for %q: %w", payload.Target.Name, err)
		}
		if err := verifyContentDescriptor(*payload.RecordTarget, patch); err != nil {
			return nil, fmt.Errorf("uup servicing: nested record for %q: %w", payload.Target.Name, err)
		}
	default:
		return nil, fmt.Errorf("uup servicing: target %q uses unsupported record type %q", payload.Target.Name, payload.RecordType)
	}
	basis, err := s.resolveExpressBasis(s.nameExpressBasis(payload.Target.Name, payload.Basis))
	if err != nil {
		return nil, fmt.Errorf("uup servicing: resolve target basis for %q: %w", payload.Target.Name, err)
	}
	target, err := msdelta.ApplyPSFRecordBounded(basis, patch, uint64(maximumCanonicalTarget))
	if err != nil {
		return target, fmt.Errorf("uup servicing: apply express record to %q: %w", payload.Target.Name, err)
	}
	if err := verifyContentDescriptor(payload.Target, target); err != nil {
		return nil, fmt.Errorf("uup servicing: reconstructed target %q: %w", payload.Target.Name, err)
	}
	return s.retainTarget(key, target, maximumCanonicalRetainedTarget), nil
}

func validatePSFRecordRange(offset, length, payloadSize int64) error {
	if offset < 0 || length < 0 || length > payloadSize || offset > payloadSize-length {
		return fmt.Errorf("invalid PSF record range offset=%d length=%d payload=%d", offset, length, payloadSize)
	}
	if length > defaultMaximumDeltaRecord {
		return fmt.Errorf("PSF record length %d exceeds %d-byte bound", length, defaultMaximumDeltaRecord)
	}
	return nil
}

// DiagnoseContentTarget reconstructs one express target while preserving the
// bounded, hash-failing output for comparison with an independent oracle. The
// normal OpenContentTarget path remains strict and never publishes that output.
func (s *CumulativeStage) DiagnoseContentTarget(name string) (storage.Reader, error) {
	if s == nil || s.Graph == nil {
		return nil, fmt.Errorf("uup servicing: stage content graph is required")
	}
	payload, found := s.expressByTarget[normalizeCIXName(name)]
	if !found {
		return nil, fmt.Errorf("uup servicing: diagnostic target %q is not an express payload", name)
	}
	data, err := s.materializeExpress(payload)
	if data == nil {
		return nil, err
	}
	return &starvalue.Bytes{Name: payload.Target.Name, Data: data}, err
}

func (s *CumulativeStage) nameExpressBasis(targetName string, descriptor *ContentDescriptor) *ContentDescriptor {
	if descriptor == nil || descriptor.Name != "" || len(s.predecessorByStem) == 0 {
		return descriptor
	}
	identity, relative, err := ParseComponentContentName(targetName)
	if err != nil {
		return descriptor
	}
	predecessor, found := s.predecessorByStem[normalizeCIXName(identity.Stem)]
	if !found || predecessor == "" {
		return descriptor
	}
	copy := *descriptor
	copy.Name = strings.TrimSuffix(predecessor, `\`) + `\` + relative
	copy.nameHint = true
	return &copy
}

func (s *CumulativeStage) resolveExpressBasis(descriptor *ContentDescriptor) ([]byte, error) {
	if descriptor == nil {
		return nil, nil
	}
	if s.assemblyResolver == nil {
		return nil, fmt.Errorf("no predecessor content resolver")
	}
	file, err := s.assemblyResolver(*descriptor)
	if err != nil && s.Graph != nil {
		// History may name identical basis bytes under several product or
		// component identities, only some of which exist in this edition.
		// Retry declared equal-content aliases through the same strict
		// resolver; never infer an alias by filename or relax the edge hash.
		seen := map[string]bool{normalizeCIXName(descriptor.Name): true}
		for _, alias := range s.Graph.Sources {
			key := normalizeCIXName(alias.Name)
			if alias.SHA256 != descriptor.SHA256 || seen[key] {
				continue
			}
			seen[key] = true
			// As in resolveEdgeBasis, the delta edge's length describes
			// its input; a history target's length can differ.
			alias.Length = descriptor.Length
			if candidate, nextErr := s.assemblyResolver(alias); nextErr == nil {
				file, err = candidate, nil
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if file.Size() != descriptor.Length || descriptor.Length < 0 || descriptor.Length > maximumCanonicalTarget {
		return nil, fmt.Errorf("basis %q has size %d, want %d", descriptor.Name, file.Size(), descriptor.Length)
	}
	data := make([]byte, descriptor.Length)
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, file.Size()), data); err != nil {
		return nil, err
	}
	if err := verifyContentDescriptor(*descriptor, data); err != nil {
		return nil, err
	}
	return data, nil
}

func verifyContentDescriptor(descriptor ContentDescriptor, data []byte) error {
	if int64(len(data)) != descriptor.Length {
		return fmt.Errorf("length %d, want %d", len(data), descriptor.Length)
	}
	if digest := sha256.Sum256(data); digest != descriptor.SHA256 {
		return fmt.Errorf("SHA-256 %x, want %x", digest, descriptor.SHA256)
	}
	return nil
}

// OpenCumulativeStage opens the metadata, PSF index, history index, and exact
// content graph from an update WIM. All nested containers remain random-access
// TinyRangeX readers; no intermediate is extracted.
func OpenCumulativeStage(outer *wim.Archive) (*CumulativeStage, error) {
	if outer == nil {
		return nil, fmt.Errorf("uup servicing: update WIM is required")
	}
	entries, err := outer.List("/image1")
	if err != nil {
		return nil, fmt.Errorf("uup servicing: list update WIM: %w", err)
	}
	var metadataName, psfName string
	for _, entry := range entries {
		if entry.Directory {
			continue
		}
		switch strings.ToLower(path.Ext(entry.Name)) {
		case ".wim":
			if metadataName != "" {
				return nil, fmt.Errorf("uup servicing: update contains multiple metadata WIMs")
			}
			metadataName = entry.Path
		case ".psf":
			if psfName != "" {
				return nil, fmt.Errorf("uup servicing: update contains multiple PSF payloads")
			}
			psfName = entry.Path
		}
	}
	if metadataName == "" || psfName == "" {
		return nil, fmt.Errorf("uup servicing: update lacks one metadata WIM and one PSF payload")
	}
	metadataFile, err := outer.OpenFile(metadataName)
	if err != nil {
		return nil, err
	}
	metadata, err := wim.Open(metadataFile)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: open metadata WIM %q: %w", metadataName, err)
	}
	psf, err := outer.OpenFile(psfName)
	if err != nil {
		return nil, err
	}
	stage := &CumulativeStage{MetadataName: metadataName, PSFName: psfName, Metadata: metadata, PSF: psf}
	if err := stage.openExpressGraph(); err != nil {
		return nil, err
	}
	return stage, nil
}

// OpenCumulativeStageParts opens the native UUP representation in which the
// express metadata and PSF are separate payloads. Metadata may be a WIM/ESD or
// a cabinet; both remain random-access TinyRangeX readers.
func OpenCumulativeStageParts(metadataName string, metadataReader storage.Reader, psfName string, psf storage.Reader) (*CumulativeStage, error) {
	return OpenCumulativeStagePayloads([]string{metadataName}, []storage.Reader{metadataReader}, psfName, psf)
}

// OpenCumulativeStagePayloads composes all complementary express metadata
// payloads (for example mumx.esd plus the CIX WIM) with one PSF record stream.
func OpenCumulativeStagePayloads(metadataNames []string, metadataReaders []storage.Reader, psfName string, psf storage.Reader) (*CumulativeStage, error) {
	cache, err := NewStageMetadataCache(bytecache.DefaultBytes)
	if err != nil {
		return nil, err
	}
	return OpenCumulativeStagePayloadsCache(metadataNames, metadataReaders, psfName, psf, cache)
}

// OpenCumulativeStagePayloadsCache is the bounded multi-stage variant used by
// update-media construction. A shared cache prevents one retained 384 MiB LRU
// per update stage.
func OpenCumulativeStagePayloadsCache(metadataNames []string, metadataReaders []storage.Reader, psfName string, psf storage.Reader, cache *StageMetadataCache) (*CumulativeStage, error) {
	if len(metadataReaders) == 0 || len(metadataNames) != len(metadataReaders) || psf == nil {
		return nil, fmt.Errorf("uup servicing: express metadata payloads and one PSF payload are required")
	}
	if cache == nil || cache.store == nil {
		return nil, fmt.Errorf("uup servicing: metadata cache is required")
	}
	stage := &CumulativeStage{MetadataName: strings.Join(metadataNames, ","), PSFName: psfName, PSF: psf}
	for index, metadataReader := range metadataReaders {
		if metadataReader == nil {
			return nil, fmt.Errorf("uup servicing: metadata %q is nil", metadataNames[index])
		}
		metadata, wimErr := wim.OpenWithCache(metadataReader, cache.store, cache.next.Add(1))
		if wimErr == nil {
			stage.metadataArchives = append(stage.metadataArchives, stageMetadataArchive{name: metadataNames[index], wim: metadata})
			if stage.Metadata == nil {
				stage.Metadata = metadata
			}
			continue
		}
		metadataCAB, cabErr := cab.Open(metadataReader, true)
		if cabErr != nil {
			return nil, fmt.Errorf("uup servicing: metadata %q is neither WIM nor cabinet (WIM: %v; CAB: %v)", metadataNames[index], wimErr, cabErr)
		}
		stage.metadataArchives = append(stage.metadataArchives, stageMetadataArchive{name: metadataNames[index], cab: metadataCAB})
		if stage.metadataCAB == nil {
			stage.metadataCAB = metadataCAB
		}
	}
	if err := stage.openExpressGraph(); err != nil {
		return nil, err
	}
	return stage, nil
}

// OpenCanonicalStage opens a non-express CBS update cabinet. It has package
// and component manifests but no PSF content graph.
func OpenCanonicalStage(name string, reader storage.Reader) (*CumulativeStage, error) {
	if reader == nil {
		return nil, fmt.Errorf("uup servicing: canonical cabinet is required")
	}
	metadata, err := cab.Open(reader, true)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: open canonical cabinet %q: %w", name, err)
	}
	var indexName string
	members := make(map[string]int64)
	for _, member := range metadata.Files() {
		members[normalizeCIXName(member.Name)] = member.Size
		if strings.EqualFold(path.Base(strings.ReplaceAll(member.Name, "\\", "/")), "_manifest_.cix.xml") {
			if indexName != "" {
				return nil, fmt.Errorf("uup servicing: canonical cabinet %q contains multiple ContainerIndexes", name)
			}
			indexName = member.Name
		}
	}
	if indexName == "" {
		return nil, fmt.Errorf("uup servicing: canonical cabinet %q lacks _manifest_.cix.xml", name)
	}
	indexFile, err := metadata.Lookup(indexName)
	if err != nil {
		return nil, err
	}
	index, err := ParseContainerIndex(io.NewSectionReader(indexFile, 0, indexFile.Size()))
	if err != nil {
		return nil, fmt.Errorf("uup servicing: canonical cabinet %q ContainerIndex: %w", name, err)
	}
	graph, err := BuildCanonicalGraph(index, members)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: canonical cabinet %q: %w", name, err)
	}
	if graph.ContainerLength > maximumCanonicalContainer {
		return nil, fmt.Errorf("uup servicing: canonical cabinet %q declares %d target bytes, exceeds %d-byte bound", name, graph.ContainerLength, maximumCanonicalContainer)
	}
	byTarget := make(map[string]DeltaPayload, len(graph.Payloads))
	for _, payload := range graph.Payloads {
		byTarget[normalizeCIXName(payload.Target.Name)] = payload
	}
	return &CumulativeStage{
		MetadataName: name, metadataCAB: metadata, Index: index, Graph: graph,
		canonicalByTarget: byTarget, canonicalCache: make(map[string][]byte),
		metadataArchives: []stageMetadataArchive{{name: name, cab: metadata}},
	}, nil
}

// OpenPlannedFile opens one file from a validated effect plan. Metadata files
// remain lazy archive members; logical payloads are reconstructed from the
// canonical cabinet's bounded RAW/PA30 DAG and verified by target SHA-256.
func (s *CumulativeStage) OpenPlannedFile(effect StageFileEffect) (storage.Reader, error) {
	switch effect.SourceMode {
	case "metadata":
		return s.openMetadataFile(effect.SourceName)
	case "payload":
		return s.OpenContentTarget(effect.SourceName)
	case "predecessor":
		if effect.SourceDescriptor == nil || s.assemblyResolver == nil {
			return nil, fmt.Errorf("uup servicing: predecessor file %q lacks an exact resolver descriptor", effect.SourceName)
		}
		return s.assemblyResolver(*effect.SourceDescriptor)
	case "installed":
		if s.assemblyNameResolver == nil {
			return nil, fmt.Errorf("uup servicing: installed file %q lacks a name resolver", effect.SourceName)
		}
		file, err := s.assemblyNameResolver(effect.SourceName)
		if err != nil {
			return nil, err
		}
		if effect.ExpectedSHA256 != nil {
			digest := sha256.New()
			if _, err := io.Copy(digest, io.NewSectionReader(file, 0, file.Size())); err != nil {
				return nil, fmt.Errorf("uup servicing: hash installed file %q: %w", effect.SourceName, err)
			}
			var got [sha256.Size]byte
			copy(got[:], digest.Sum(nil))
			if got != *effect.ExpectedSHA256 {
				return nil, fmt.Errorf("uup servicing: installed file %q does not match manifest SHA-256", effect.SourceName)
			}
		}
		return file, nil
	default:
		return nil, fmt.Errorf("uup servicing: file %q has unsupported source mode %q", effect.SourceName, effect.SourceMode)
	}
}

func (s *CumulativeStage) hasContentTarget(name string) bool {
	if s == nil || s.Graph == nil {
		return false
	}
	key := normalizeCIXName(name)
	if _, found := s.expressByTarget[key]; found {
		return true
	}
	if _, found := s.canonicalByTarget[key]; found {
		return true
	}
	_, found := s.carryTarget(name)
	return found
}

// Stage graphs are immutable after opening. Keep the first matching carry,
// as the previous linear lookup did, without rescanning aliases for each file.
func (s *CumulativeStage) carryTarget(name string) (CarryPayload, bool) {
	if s == nil || s.Graph == nil {
		return CarryPayload{}, false
	}
	s.carryIndexOnce.Do(func() {
		s.carryByTarget = make(map[string]CarryPayload, len(s.Graph.Carries))
		for _, carry := range s.Graph.Carries {
			key := normalizeCIXName(carry.Target.Name)
			if _, exists := s.carryByTarget[key]; !exists {
				s.carryByTarget[key] = carry
			}
		}
	})
	carry, found := s.carryByTarget[normalizeCIXName(name)]
	return carry, found
}

// OpenContentTarget materializes one named logical target from a stage graph.
// It is primarily the narrow inspection boundary for reconstruction probes.
func (s *CumulativeStage) OpenContentTarget(name string) (storage.Reader, error) {
	if s == nil || s.Graph == nil {
		return nil, fmt.Errorf("uup servicing: stage content graph is required")
	}
	if payload, found := s.expressByTarget[normalizeCIXName(name)]; found {
		data, err := s.materializeExpress(payload)
		if err != nil {
			return nil, err
		}
		return &starvalue.Bytes{Name: payload.Target.Name, Data: data}, nil
	}
	if carry, found := s.carryTarget(name); found {
		if s.assemblyResolver == nil {
			return nil, fmt.Errorf("uup servicing: carried target %q has no predecessor resolver", name)
		}
		return s.assemblyResolver(carry.Source)
	}
	data, err := s.materializeCanonical(name, make(map[string]struct{}))
	if err != nil {
		return nil, err
	}
	return &starvalue.Bytes{Name: name, Data: data}, nil
}

// openTargetDescriptor finds one exact logical target by length and SHA-256.
// Names are used only to reject a conflicting named edge; content identity is
// authoritative across versioned WinSxS paths.
func (s *CumulativeStage) openTargetDescriptor(descriptor ContentDescriptor) (storage.Reader, bool, error) {
	if s == nil || s.Graph == nil {
		return nil, false, nil
	}
	var found *DeltaPayload
	for index := range s.Graph.Payloads {
		payload := &s.Graph.Payloads[index]
		if payload.Target.Length != descriptor.Length || payload.Target.SHA256 != descriptor.SHA256 {
			continue
		}
		if found == nil || (descriptor.Name != "" && normalizeCIXName(payload.Target.Name) == normalizeCIXName(descriptor.Name)) {
			found = payload
		}
	}
	if found == nil {
		var carry *CarryPayload
		for index := range s.Graph.Carries {
			candidate := &s.Graph.Carries[index]
			if candidate.Target.Length != descriptor.Length || candidate.Target.SHA256 != descriptor.SHA256 {
				continue
			}
			if carry == nil || (descriptor.Name != "" && normalizeCIXName(candidate.Target.Name) == normalizeCIXName(descriptor.Name)) {
				carry = candidate
			}
		}
		if carry == nil {
			return nil, false, nil
		}
		if s.assemblyResolver == nil {
			return nil, false, fmt.Errorf("carried target %q has no predecessor resolver", carry.Target.Name)
		}
		file, err := s.assemblyResolver(carry.Source)
		if err == nil {
			return file, true, nil
		}
		// History can carry identical bytes under several component names,
		// including components absent from this base edition. A missing first
		// alias must not hide another declared, hash-exact predecessor. Every
		// candidate still passes through the strict descriptor resolver; this
		// does not change named-target lookup or retry failed delta payloads.
		seen := map[ContentDescriptor]struct{}{carry.Source: {}}
		for _, candidate := range s.Graph.Carries {
			if candidate.Target.Length != descriptor.Length || candidate.Target.SHA256 != descriptor.SHA256 {
				continue
			}
			if _, duplicate := seen[candidate.Source]; duplicate {
				continue
			}
			seen[candidate.Source] = struct{}{}
			if file, nextErr := s.assemblyResolver(candidate.Source); nextErr == nil {
				return file, true, nil
			}
		}
		return nil, false, err
	}
	var data []byte
	var err error
	if s.expressByTarget != nil {
		data, err = s.materializeExpress(*found)
	} else {
		data, err = s.materializeCanonical(found.Target.Name, make(map[string]struct{}))
	}
	if err != nil {
		return nil, false, err
	}
	return &starvalue.Bytes{Name: found.Target.Name, Data: data}, true, nil
}

func (s *CumulativeStage) materializeCanonical(name string, visiting map[string]struct{}) ([]byte, error) {
	key := normalizeCIXName(name)
	s.canonicalMu.Lock()
	if cached := s.canonicalCache[key]; cached != nil {
		s.canonicalMu.Unlock()
		return cached, nil
	}
	s.canonicalMu.Unlock()
	payload, found := s.canonicalByTarget[key]
	if !found || s.metadataCAB == nil {
		return nil, fmt.Errorf("uup servicing: canonical target %q is unavailable", name)
	}
	if _, cycle := visiting[key]; cycle {
		return nil, fmt.Errorf("uup servicing: canonical target %q contains a basis cycle", name)
	}
	visiting[key] = struct{}{}
	defer delete(visiting, key)
	if payload.Target.Length < 0 || payload.Target.Length > maximumCanonicalTarget || payload.Record.Length < 0 || payload.Record.Length > defaultMaximumDeltaRecord {
		return nil, fmt.Errorf("uup servicing: canonical target %q exceeds materialization bounds", name)
	}
	record, err := s.metadataCAB.Lookup(payload.Record.Name)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: open canonical record %q: %w", payload.Record.Name, err)
	}
	data := make([]byte, record.Size())
	if _, err := io.ReadFull(io.NewSectionReader(record, 0, record.Size()), data); err != nil {
		return nil, fmt.Errorf("uup servicing: read canonical record %q: %w", payload.Record.Name, err)
	}
	if digest := sha256.Sum256(data); digest != payload.Record.SHA256 {
		return nil, fmt.Errorf("uup servicing: canonical record %q SHA-256 mismatch", payload.Record.Name)
	}
	var target []byte
	switch payload.RecordType {
	case "RAW":
		target = data
	case "PA30":
		var basis []byte
		if payload.Basis != nil {
			basis, err = s.materializeCanonical(payload.Basis.Name, visiting)
			if err != nil {
				return nil, fmt.Errorf("uup servicing: materialize basis for %q: %w", name, err)
			}
		}
		target, err = msdelta.ApplyBounded(basis, data, uint64(maximumCanonicalTarget))
		if err != nil {
			return nil, fmt.Errorf("uup servicing: apply canonical record %q to %q: %w", payload.Record.Name, name, err)
		}
	default:
		return nil, fmt.Errorf("uup servicing: canonical target %q uses unsupported record type %q", name, payload.RecordType)
	}
	if int64(len(target)) != payload.Target.Length || sha256.Sum256(target) != payload.Target.SHA256 {
		return nil, fmt.Errorf("uup servicing: reconstructed canonical target %q does not match its length/SHA-256", name)
	}
	return s.retainTarget(key, target, maximumCanonicalRetainedTarget), nil
}

func (s *CumulativeStage) openExpressGraph() error {
	entries, err := s.metadataEntries()
	if err != nil {
		return err
	}
	var indexName string
	for _, entry := range entries {
		if strings.EqualFold(entry.Name, "express.psf.cix.xml") {
			if indexName != "" {
				return fmt.Errorf("uup servicing: metadata contains multiple PSF indexes")
			}
			indexName = entry.Path
		}
	}
	if indexName == "" {
		return fmt.Errorf("uup servicing: metadata lacks express.psf.cix.xml")
	}
	indexFile, err := s.openMetadataFile(indexName)
	if err != nil {
		return fmt.Errorf("uup servicing: open PSF index: %w", err)
	}
	index, err := ParseContainerIndex(io.NewSectionReader(indexFile, 0, indexFile.Size()))
	if err != nil {
		return err
	}
	var historyRecord *CIXFile
	for recordIndex := range index.Files {
		if strings.EqualFold(path.Base(strings.ReplaceAll(index.Files[recordIndex].Name, "\\", "/")), "historycix.cab") {
			if historyRecord != nil {
				return fmt.Errorf("uup servicing: PSF index contains multiple history cabinets")
			}
			historyRecord = &index.Files[recordIndex]
		}
	}
	if historyRecord == nil && len(index.Files) == 0 {
		if index.Length < 0 || index.Length > s.PSF.Size() {
			return fmt.Errorf("uup servicing: empty PSF index length %d exceeds payload size %d", index.Length, s.PSF.Size())
		}
		s.Graph = &CumulativeGraph{ContainerLength: index.Length}
		s.expressByTarget = make(map[string]DeltaPayload)
		s.canonicalCache = make(map[string][]byte)
		return nil
	}
	if historyRecord == nil || len(historyRecord.Sources) != 1 {
		return fmt.Errorf("uup servicing: PSF index has no unambiguous history cabinet")
	}
	historySource := historyRecord.Sources[0]
	if historySource.Type != "RAW" || historySource.Offset < 0 || historySource.Length <= 0 || historySource.Offset > index.Length-historySource.Length || historySource.Hash != historyRecord.Hash {
		return fmt.Errorf("uup servicing: history cabinet has an invalid PSF range")
	}
	historyReader := io.NewSectionReader(s.PSF, historySource.Offset, historySource.Length)
	digest := sha256.New()
	if _, err := io.Copy(digest, historyReader); err != nil {
		return fmt.Errorf("uup servicing: hash history cabinet: %w", err)
	}
	if !equalHashBytes(historyRecord.Hash, digest.Sum(nil)) {
		return fmt.Errorf("uup servicing: history cabinet SHA-256 mismatch")
	}
	historyCAB, err := cab.Open(io.NewSectionReader(s.PSF, historySource.Offset, historySource.Length), false)
	if err != nil {
		return fmt.Errorf("uup servicing: open history cabinet: %w", err)
	}
	var historyName string
	for _, member := range historyCAB.Files() {
		if strings.EqualFold(path.Base(strings.ReplaceAll(member.Name, "\\", "/")), "history.cix.xml") {
			historyName = member.Name
			break
		}
	}
	if historyName == "" {
		return fmt.Errorf("uup servicing: history cabinet lacks history.cix.xml")
	}
	historyFile, err := historyCAB.Lookup(historyName)
	if err != nil {
		return err
	}
	history, err := ParseContainerIndex(io.NewSectionReader(historyFile, 0, historyFile.Size()))
	if err != nil {
		return err
	}
	graph, err := BuildCumulativeGraphWithRecords(index, history, s.PSF, defaultMaximumDeltaRecord)
	if err != nil {
		return err
	}
	// The graph is the compact executable form. Retaining both parsed CIX trees
	// keeps every unselected filename/source node alive across all update stages.
	s.Index, s.History, s.Graph = nil, nil, graph
	s.expressByTarget = make(map[string]DeltaPayload, len(graph.Payloads))
	for _, payload := range graph.Payloads {
		key := normalizeCIXName(payload.Target.Name)
		if _, exists := s.expressByTarget[key]; exists {
			return fmt.Errorf("uup servicing: duplicate express target %q", payload.Target.Name)
		}
		s.expressByTarget[key] = payload
	}
	s.canonicalCache = make(map[string][]byte)
	return nil
}
