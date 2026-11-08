package native

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// Exact store staging deliberately does not reuse preliminary admission or its
// runtime activation flags. File opening uses the same native reconstruction and
// hash verification as other planned content. Catalog trust, deployment state,
// installed sources, driver operations and activation remain separate work.
func exactComponentPlanBuiltin(stage *uup.CumulativeStage, index *uup.ComponentMetadataIndex) *starlark.Builtin {
	return starlark.NewBuiltin("servicing_metadata.plan_components", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var values, snapshots *starlark.List
		if err := starlark.UnpackArgs("servicing_metadata.plan_components", args, kwargs, "identities", &values, "manifests?", &snapshots); err != nil {
			return nil, err
		}
		if values.Len() > 1<<20 {
			return nil, fmt.Errorf("component staging request exceeds bound")
		}
		identities := make([][]byte, values.Len())
		total := 0
		for i := range identities {
			identity, ok := values.Index(i).(starlark.Bytes)
			if !ok || len(identity) > 64<<10 {
				return nil, fmt.Errorf("component staging identity %d must be bytes within 64 KiB", i)
			}
			total += len(identity)
			if total > 64<<20 {
				return nil, fmt.Errorf("component staging identities exceed 64 MiB")
			}
			identities[i] = []byte(identity)
		}
		var manifests []*uup.ParsedAssemblyFile
		if snapshots != nil {
			if snapshots.Len() != len(identities) {
				return nil, fmt.Errorf("component manifest snapshot count differs from identities")
			}
			manifests = make([]*uup.ParsedAssemblyFile, len(identities))
			for i := range manifests {
				reader, ok := snapshots.Index(i).(*starvalue.ReaderValue)
				if !ok {
					return nil, fmt.Errorf("component manifest %d must be an owned metadata snapshot", i)
				}
				manifests[i], ok = reader.StorageReader().(*uup.ParsedAssemblyFile)
				if !ok {
					return nil, fmt.Errorf("component manifest %d must be an owned metadata snapshot", i)
				}
			}
		}
		components, err := index.PlanComponentsWithManifests(identities, manifests)
		if err != nil {
			return nil, err
		}
		plan, err := uup.PlanStageEffects(stage, uup.StageAssemblyPlan{Components: components})
		if err != nil {
			return nil, err
		}
		descriptions, err := uup.PlanCSIComponentDescriptions(stage, components)
		if err != nil {
			return nil, err
		}
		return componentStagingRecord(stage, plan, descriptions)
	})
}

func componentStagingRecord(stage *uup.CumulativeStage, plan uup.StageEffectPlan, descriptions []uup.CSIComponentRecord) (starlark.Value, error) {
	if len(plan.RegistryKeys) != 0 || len(plan.RegistryValues) != 0 {
		return nil, fmt.Errorf("store-only component plan contains runtime registry effects")
	}
	files := make([]starlark.Value, len(plan.Files))
	for i, effect := range plan.Files {
		if len(effect.Destinations) != 0 {
			return nil, fmt.Errorf("store-only component plan contains runtime links")
		}
		var recoveryBasis starlark.Value = starlark.None
		basis, err := stage.PlannedRecoveryBasis(effect)
		if err != nil {
			return nil, err
		}
		if basis != nil {
			recoveryBasis = starvalue.NewRecord(starlark.StringDict{"name": starlark.String(basis.Name), "size": starlark.MakeInt64(basis.Length), "sha256": starlark.Bytes(basis.SHA256[:])})
		}
		files[i] = starvalue.NewRecord(starlark.StringDict{
			"recovery_basis": recoveryBasis, "file_key": starlark.String(effect.CSIFileKey),
			"store_path":  starlark.String(effect.StorePath),
			"kind":        starlark.String(effect.Kind),
			"source_name": starlark.String(effect.SourceName),
			"source_mode": starlark.String(effect.SourceMode),
		})
	}
	order := stage.PlannedFileReadOrder(plan.Files)
	readOrder := make([]starlark.Value, len(order))
	for i, n := range order {
		readOrder[i] = starlark.MakeInt(n)
	}
	// Keep adjacent reads cheap without retaining full decoded targets alongside
	// guest RAM. The compressed LRU also serializes full-target reconstruction.
	// Oversized supported targets are admitted alone; ordinary entries share
	// a smaller working set instead of occupying the maximum target budget.
	contentCache, err := newStageContentCache(128 << 20)
	if err != nil {
		return nil, err
	}
	normalize := func(name string) string {
		return strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(name, "/", `\`), `\`))
	}
	declaredSizes := make(map[string]int64)
	declaredHashes := make(map[string][32]byte)
	if stage.Graph != nil {
		for _, p := range stage.Graph.Payloads {
			declaredSizes[normalize(p.Target.Name)] = p.Target.Length
			declaredHashes[normalize(p.Target.Name)] = p.Target.SHA256
		}
		for _, p := range stage.Graph.Carries {
			if _, exists := declaredSizes[normalize(p.Target.Name)]; exists {
				continue
			}
			declaredSizes[normalize(p.Target.Name)] = p.Target.Length
			declaredHashes[normalize(p.Target.Name)] = p.Target.SHA256
		}
	}
	// Distinct paths with exactly the same declared content identity may
	// share bytes only within this plan's verified cache. Unknown identities
	// keep separate keys. No data becomes available before a loader verifies
	// the complete content against its declared length and SHA-256.
	contentKeys := make([]int, len(plan.Files))
	contentIDs := make(map[stageContentIdentity]int)
	for i, effect := range plan.Files {
		contentKeys[i] = i
		size, hash, known := declaredStageContent(effect, declaredSizes, declaredHashes, normalize)
		// A second manifest's legacy digest needs its own validation, even
		// when modern content identity matches a previously verified alias.
		if !known || effect.ExpectedSHA1 != nil {
			continue
		}
		identity := stageContentIdentity{size: size, hash: hash}
		if key, exists := contentIDs[identity]; exists {
			contentKeys[i] = key
		} else {
			contentIDs[identity] = i
		}
	}
	open := starlark.NewBuiltin("component_staging.open", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var i int
		var lazy bool
		if err := starlark.UnpackArgs("component_staging.open", args, kwargs, "index", &i, "lazy?", &lazy); err != nil {
			return nil, err
		}
		if i < 0 || i >= len(plan.Files) {
			return nil, fmt.Errorf("component staging file index out of range")
		}
		effect := plan.Files[i]
		var file storage.Reader
		if lazy {
			// Borrow declared lengths without decoding unused payloads. Integrity
			// is checked on first read and after shared-cache eviction.
			size, digest, known := declaredStageContent(effect, declaredSizes, declaredHashes, normalize)
			if !known {
				var err error
				file, err = stage.OpenPlannedFile(effect)
				if err != nil {
					return nil, err
				}
				size = file.Size()
			}
			if size < 0 || size > 512<<20 {
				return nil, fmt.Errorf("staged file exceeds lazy read bound")
			}
			reader := &reopenedStageReader{size: size, compressed: contentCache, key: bytecache.Key{Index: contentKeys[i]}, open: func() (storage.Reader, error) { return stage.OpenPlannedFile(effect) }}
			if known {
				reader.expectedSHA256 = &digest
			}
			return starvalue.NewReader(effect.StorePath, reader), nil
		}
		var err error
		file, err = stage.OpenPlannedFile(effect)
		if err != nil {
			return nil, err
		}
		value, ok := file.(starlark.Value)
		if !ok {
			return nil, fmt.Errorf("component staging file is not a Starlark file")
		}
		return value, nil
	})

	deltaInputs := starlark.NewBuiltin("component_staging.delta_inputs", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var i int
		if err := starlark.UnpackArgs("component_staging.delta_inputs", args, kwargs, "index", &i); err != nil {
			return nil, err
		}
		if i < 0 || i >= len(plan.Files) {
			return nil, fmt.Errorf("component staging index out of range")
		}
		effect := plan.Files[i]
		if effect.SourceMode != "payload" {
			return nil, fmt.Errorf("component staging file is not a delta payload")
		}
		inputs, err := stage.InspectExpressDeltaInputs(effect.SourceName)
		if err != nil {
			return nil, err
		}
		return starvalue.NewRecord(starlark.StringDict{
			"source":        starvalue.NewReader("delta basis", &starvalue.Bytes{Data: inputs.Source}),
			"delta":         starvalue.NewReader("delta record", &starvalue.Bytes{Data: inputs.Delta}),
			"psf_record":    starlark.Bool(inputs.PSFRecord),
			"target_name":   starlark.String(inputs.Target.Name),
			"target_size":   starlark.MakeInt64(inputs.Target.Length),
			"target_sha256": starlark.Bytes(inputs.Target.SHA256[:]),
		}), nil
	})
	recoveryInfo := starlark.NewBuiltin("component_staging.recovery_info", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var i int
		if err := starlark.UnpackArgs("component_staging.recovery_info", args, kwargs, "index", &i); err != nil {
			return nil, err
		}
		if i < 0 || i >= len(plan.Files) {
			return nil, fmt.Errorf("component staging file index out of range")
		}
		f, err := stage.PlannedRecoveryFile(plan.Files[i])
		if err != nil {
			return nil, err
		}
		if f == nil {
			return starlark.None, nil
		}
		sources := make([]starlark.Value, len(f.Sources))
		for j, s := range f.Sources {
			sources[j] = starvalue.NewRecord(starlark.StringDict{
				"name": starlark.String(s.Name), "type": starlark.String(s.Type), "offset": starlark.MakeInt64(s.Offset), "length": starlark.MakeInt64(s.Length), "sha256": starlark.Bytes(s.Hash[:]),
			})
		}
		return starvalue.NewRecord(starlark.StringDict{"name": starlark.String(f.Name), "size": starlark.MakeInt64(f.Length), "sha256": starlark.Bytes(f.Hash[:]), "sources": starlark.NewList(sources), "basis_count": starlark.MakeInt(len(f.Bases))}), nil
	})
	inherited := starlark.NewBuiltin("component_staging.inherited_recovery", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var i int
		if err := starlark.UnpackArgs("component_staging.inherited_recovery", args, kwargs, "index", &i); err != nil {
			return nil, err
		}
		if i < 0 || i >= len(plan.Files) {
			return nil, fmt.Errorf("component staging index out of range")
		}
		data, err := stage.InheritedPlannedRecovery(plan.Files[i])
		if err != nil {
			return nil, err
		}
		if data == nil {
			return starlark.None, nil
		}
		return starvalue.NewRecord(starlark.StringDict{"file": starvalue.NewReader("inherited recovery", &starvalue.Bytes{Data: data.Data}), "source_path": starlark.String(data.SourcePath)}), nil
	})
	// Recovery records can total gigabytes. Keep only a shared bounded cache;
	// evicted records are regenerated from the same admitted forward edge.
	recoveryCache := bytecache.New(128 << 20)
	reverse := starlark.NewBuiltin("component_staging.create_recovery", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var i int
		var fileTime uint64
		var lazy bool
		if err := starlark.UnpackArgs("component_staging.create_recovery", args, kwargs, "index", &i, "target_filetime", &fileTime, "lazy?", &lazy); err != nil {
			return nil, err
		}
		if i < 0 || i >= len(plan.Files) {
			return nil, fmt.Errorf("component staging index out of range")
		}
		if lazy {
			reader, err := newRecoveryReader(recoveryCache, bytecache.Key{Source: fileTime, Index: i}, func() ([]byte, error) {
				return stage.CreatePlannedRecovery(plan.Files[i], fileTime)
			})
			if err != nil {
				return nil, err
			}
			return starvalue.NewReader("recovery", reader), nil
		}
		record, err := stage.CreatePlannedRecovery(plan.Files[i], fileTime)
		if err != nil {
			return nil, err
		}
		return starvalue.NewReader("recovery", &starvalue.Bytes{Data: record}), nil
	})
	components := make([]starlark.Value, len(descriptions))
	for i, record := range descriptions {
		values := starlark.NewDict(len(record.Files))
		for _, file := range record.Files {
			if err := values.SetKey(starlark.String(file.Name), starlark.MakeUint64(uint64(file.Flags))); err != nil {
				return nil, err
			}
		}
		components[i] = starvalue.NewRecord(starlark.StringDict{
			"stem": starlark.String(record.Stem), "identity": starlark.Bytes(record.Identity),
			"manifest_sha256": starlark.Bytes(record.ManifestSHA256[:]), "files": values,
		})
	}
	result := starvalue.NewRecord(starlark.StringDict{
		"components": starlark.NewList(components), "files": starlark.NewList(files), "read_order": starlark.NewList(readOrder), "open": open,
		"delta_inputs": deltaInputs, "cache_stats": componentCacheStatsBuiltin(contentCache), "recovery_info": recoveryInfo, "create_recovery": reverse, "inherited_recovery": inherited,
	})
	result.Freeze()
	return result, nil
}

// reopenedStageReader does not pin every decoded component in the image tree.
// Its opener must return the same verified immutable content on every call.
type reopenedStageReader struct {
	expectedSHA256 *[32]byte
	verified       atomic.Bool
	cache          *bytecache.Cache // Recovery records use the existing raw cache.
	compressed     *stageContentCache
	key            bytecache.Key
	size           int64
	open           func() (storage.Reader, error)
}

func (r *reopenedStageReader) VerifiedSHA256() ([32]byte, bool) {
	if r.expectedSHA256 != nil && r.verified.Load() {
		return *r.expectedSHA256, true
	}
	return [32]byte{}, false
}

func (r *reopenedStageReader) Size() int64 { return r.size }
func (r *reopenedStageReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative staged file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	if r.compressed != nil {
		file, err := r.compressed.get(r)
		if err != nil {
			return 0, err
		}
		if r.expectedSHA256 != nil {
			r.verified.Store(true)
		}
		return file.ReadAt(p, off)
	}

	if r.cache != nil {
		data, err := r.cache.Get(r.key, func() ([]byte, error) {
			data, err := loadStageContent(r)
			if err != nil {
				return nil, err
			}
			return bytes.Clone(data), nil
		})
		if err != nil {
			return 0, err
		}
		if r.expectedSHA256 != nil {
			r.verified.Store(true)
		}
		n := copy(p, data[off:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}
	f, err := r.open()
	if err != nil {
		return 0, err
	}
	if f.Size() != r.size {
		return 0, fmt.Errorf("staged file length changed")
	}
	return f.ReadAt(p, off)
}
