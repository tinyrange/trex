package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	storagenative "github.com/tinyrange/trex/storage/native"
	starvalue "github.com/tinyrange/trex/storage/star"
	windowsupdate "github.com/tinyrange/trex/windows/update"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

const (
	maximumAggregatedMetadata = int64(256 << 20)
	maximumEditionMetadata    = int64(2 << 30)
	maximumReferencePayload   = int64(8 << 30)
	maximumCanonicalFolder    = int64(2 << 30)
	maximumCanonicalResources = int64(8 << 30)
	// Windows 11 reference ESDs have 64 MiB solid LZMS chunks. Even the
	// initial font set exceeds the generic six-chunk archive cache: reading
	// 335 font headers again decoded another 518 MiB. Keep a larger shared
	// source working set, independently of the serviced-file cache. This is
	// a lazy ceiling; callers must budget it alongside guest memory.
	maximumWIMChunkCache     = int64(2 << 30)
	maximumServicingWIMCache = int64(256 << 20)
	// Only the RAM hot cache is bounded. Downloaded source ranges persist
	// without eviction in the native UUP cache across readers and runs.
	maximumHTTPRangeCache = int64(256 << 20)
	maximumCabinetWorkers = 4
)

type sharedByteBudget struct {
	cond  *sync.Cond
	limit int64
	used  int64
}

func newSharedByteBudget(limit int64) *sharedByteBudget {
	return &sharedByteBudget{cond: sync.NewCond(&sync.Mutex{}), limit: limit}
}

func (b *sharedByteBudget) Acquire(size int64) error {
	if size < 0 || size > b.limit {
		return fmt.Errorf("request %d exceeds %d-byte budget", size, b.limit)
	}
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	for b.used+size > b.limit {
		b.cond.Wait()
	}
	b.used += size
	return nil
}

func (b *sharedByteBudget) Release(size int64) {
	b.cond.L.Lock()
	b.used -= size
	if b.used < 0 {
		b.used = 0
	}
	b.cond.Broadcast()
	b.cond.L.Unlock()
}

// MediaBuiltin prepares the caller-selected catalog revision as referenced
// UUP media, not a bootable disk. It never discovers or ranks offers. Native
// source-range caching does not persist parsed or constructed intermediates.
func MediaBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var catalogArg, offerArg starlark.Value
	var architecture, edition, language, metadataName, targetCompDB string
	indexOnly := false
	planOnly := false
	metadataOnly := false
	stateOnly := false
	installedStageLimit := 0
	if err := starlark.UnpackArgs("update_media", args, kwargs,
		"catalog", &catalogArg, "offer", &offerArg,
		"architecture", &architecture, "edition", &edition, "language", &language,
		"metadata_name", &metadataName, "target_compdb", &targetCompDB,
		"index_only?", &indexOnly,
		"plan_only?", &planOnly,
		"metadata_only?", &metadataOnly,
		"state_only?", &stateOnly,
		"installed_stage_limit?", &installedStageLimit,
	); err != nil {
		return nil, err
	}
	if installedStageLimit < 0 {
		return nil, fmt.Errorf("update_media: installed_stage_limit must not be negative")
	}
	if metadataOnly && (indexOnly || planOnly || stateOnly || installedStageLimit != 0) {
		return nil, fmt.Errorf("update_media: metadata_only cannot be combined with image/planning modes")
	}
	catalog, offer, err := selectedOffer(catalogArg, offerArg)
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]string{"architecture": architecture, "edition": edition, "language": language, "metadata_name": metadataName, "target_compdb": targetCompDB} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("update_media: explicit %s is required", name)
		}
	}
	mediaStarted := time.Now()
	progress := func(message string) {
		if !indexOnly {
			return
		}
		if thread.Print != nil {
			thread.Print(thread, message)
		} else {
			fmt.Println(message)
		}
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, fmt.Errorf("update_media: %w", err)
	}
	httpClient, err := microsoftUpdateHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("update_media: initialize Microsoft transport: %w", err)
	}
	closure, files, err := catalog.resolveFiles(resources.Context(), offer)
	if err != nil {
		return nil, fmt.Errorf("update_media: resolve %q: %w", offer.Title, err)
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("update_media: locate persistent UUP cache: %w", err)
	}
	diskCache, err := storagenative.NewHTTPRangeDiskCache(filepath.Join(cacheRoot, "tinyrangex", "uup"))
	if err != nil {
		return nil, fmt.Errorf("update_media: initialize persistent UUP cache: %w", err)
	}
	rangePool, err := storagenative.NewPersistentHTTPRangePool(0, maximumHTTPRangeCache, httpClient,
		payloadLocationResolver(files, func(ctx context.Context) ([]windowsupdate.File, error) {
			return catalog.protocol.ResolveFilesForOffers(ctx, catalog.options, closure)
		}), diskCache)
	if err != nil {
		return nil, fmt.Errorf("update_media: initialize bounded HTTP reader: %w", err)
	}
	aggregated, err := findOfferFile(files, func(name string) bool {
		return strings.EqualFold(name, metadataName)
	})
	if err != nil {
		return nil, fmt.Errorf("update_media: %w", err)
	}
	aggregatedFile, err := openPayload(resources, rangePool, aggregated, maximumAggregatedMetadata)
	if err != nil {
		return nil, fmt.Errorf("update_media: aggregated metadata: %w", err)
	}
	aggregatedCAB, err := cab.Open(aggregatedFile, false)
	if err != nil {
		return nil, fmt.Errorf("update_media: open aggregated metadata: %w", err)
	}
	compositionMetadata := make([]starlark.Value, 0, len(aggregatedCAB.Files()))
	for _, member := range aggregatedCAB.Files() {
		compositionMetadata = append(compositionMetadata, starlark.String(member.Name))
	}
	databases, err := compositionDatabases(aggregatedCAB)
	if err != nil {
		return nil, fmt.Errorf("update_media: composition catalog: %w", err)
	}
	// Keep malformed/incomplete edition graphs inspectable without weakening
	// their required-dependency checks or starting image construction.
	if metadataOnly {
		openComposition := starlark.NewBuiltin("open_composition", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("open_composition", args, kwargs, "name", &name); err != nil {
				return nil, err
			}
			db, err := compositionDatabaseFromCatalog(databases, name)
			if err != nil {
				return nil, err
			}
			return compositionDatabaseRecord(db), nil
		})
		return starvalue.NewRecord(starlark.StringDict{
			"kind":     starlark.String("windows-update-metadata"),
			"offer_id": starlark.String(offer.ID), "offer_revision": starlark.MakeInt(offer.Revision),
			"offer_title":   starlark.String(offer.Title),
			"metadata_name": starlark.String(aggregated.Name), "metadata_sha256": starlark.String(aggregated.DigestSHA256),
			"aggregated_metadata":  aggregatedFile,
			"composition_metadata": starlark.NewList(compositionMetadata),
			"composition_catalog":  starlark.NewList(compositionCatalogRecords(databases)),
			"open_composition":     openComposition,
		}), nil
	}
	database, err := compositionDatabaseFromCatalog(databases, targetCompDB)
	if err != nil {
		return nil, fmt.Errorf("update_media: %w", err)
	}
	plan, err := uup.PlanEditionCatalog(database, databases, files, edition, language)
	if err != nil {
		return nil, fmt.Errorf("update_media: offer %q revision %d (%s), metadata %q SHA256 %s: %w", offer.ID, offer.Revision, offer.Title, aggregated.Name, aggregated.DigestSHA256, err)
	}
	updateSources, updateContainers, err := indexUpdatePayloadSources(resources, rangePool, files)
	if err != nil {
		return nil, fmt.Errorf("update_media: index update containers: %w", err)
	}
	updateStages, err := uup.PlanUpdateStagesFromSources(databases, updateSources, architecture)
	if err != nil {
		return nil, fmt.Errorf("update_media: update stages: %w", err)
	}
	progress(fmt.Sprintf("update_media: reason graph resolved after %s", time.Since(mediaStarted).Round(time.Millisecond)))
	updateStageValues := make([]starlark.Value, 0, len(updateStages))
	var updateBytes int64
	for _, stage := range updateStages {
		payloads := make([]starlark.Value, 0, len(stage.Payloads))
		for _, payload := range stage.Payloads {
			if payload.Selected {
				updateBytes += payload.Source.Size
			}
			payloads = append(payloads, starvalue.NewRecord(starlark.StringDict{
				"container":  starlark.String(payload.Source.Container.Name),
				"member":     starlark.String(payload.Source.Member),
				"name":       starlark.String(payload.Source.Name),
				"package_id": starlark.String(payload.PackageID),
				"role":       starlark.String(payload.Role),
				"selected":   starlark.Bool(payload.Selected),
				"sha256":     starlark.String(payload.DigestSHA256),
				"size":       starlark.MakeInt64(payload.Source.Size),
			}))
		}
		dependencies := make([]starlark.Value, 0, len(stage.Dependencies))
		for _, dependency := range stage.Dependencies {
			dependencies = append(dependencies, starvalue.NewRecord(starlark.StringDict{
				"feature_id": starlark.String(dependency.FeatureID),
				"kind":       starlark.String(dependency.Kind),
			}))
		}
		updateStageValues = append(updateStageValues, starvalue.NewRecord(starlark.StringDict{
			"database":          starlark.String(stage.DatabaseName),
			"database_source":   starlark.String(stage.DatabaseSource),
			"dependencies":      starlark.NewList(dependencies),
			"feature_id":        starlark.String(stage.FeatureID),
			"feature_type":      starlark.String(stage.FeatureType),
			"os_version":        starlark.String(stage.OSVersion),
			"payloads":          starlark.NewList(payloads),
			"representation":    starlark.String(stage.Representation),
			"scope":             starlark.String(stage.Scope),
			"target_os_version": starlark.String(stage.TargetOSVersion),
		}))
	}
	if planOnly {
		openComposition := starlark.NewBuiltin("open_composition", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("open_composition", args, kwargs, "name", &name); err != nil {
				return nil, err
			}
			database, err := compositionDatabaseFromCatalog(databases, name)
			if err != nil {
				return nil, fmt.Errorf("open_composition: %w", err)
			}
			return compositionDatabaseRecord(database), nil
		})
		openUpdatePayload := starlark.NewBuiltin("open_update_payload", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var featureID, name string
			if err := starlark.UnpackArgs("open_update_payload", args, kwargs, "feature_id", &featureID, "name", &name); err != nil {
				return nil, err
			}
			var match *uup.UpdatePayload
			for stageIndex := range updateStages {
				if !strings.EqualFold(updateStages[stageIndex].FeatureID, featureID) {
					continue
				}
				for payloadIndex := range updateStages[stageIndex].Payloads {
					payload := &updateStages[stageIndex].Payloads[payloadIndex]
					if strings.EqualFold(payload.Source.Name, name) {
						if match != nil {
							return nil, fmt.Errorf("open_update_payload: ambiguous payload %q", name)
						}
						match = payload
					}
				}
			}
			if match == nil {
				return nil, fmt.Errorf("open_update_payload: unknown stage payload %q for %q", name, featureID)
			}
			reader, err := openUpdatePayload(resources, rangePool, updateContainers, *match, maximumReferencePayload)
			if err != nil {
				return nil, err
			}
			value, ok := reader.(starlark.Value)
			if !ok {
				return nil, fmt.Errorf("open_update_payload: payload reader is not a Starlark value")
			}
			return value, nil
		})
		return starvalue.NewRecord(starlark.StringDict{
			"architecture":          starlark.String(database.Architecture),
			"build_info":            starlark.String(database.BuildInfo),
			"composition_count":     starlark.MakeInt(len(databases)),
			"composition_databases": starlark.NewList(compositionCatalogRecords(databases)),
			"composition_metadata":  starlark.NewList(compositionMetadata),
			"edition":               starlark.String(strings.ToLower(edition)),
			"kind":                  starlark.String("windows-update-plan"),
			"language":              starlark.String(strings.ToLower(language)),
			"offer_id":              starlark.String(offer.ID),
			"offer_revision":        starlark.MakeInt(offer.Revision),
			"offer_title":           starlark.String(offer.Title),
			"open_composition":      openComposition,
			"open_update_payload":   openUpdatePayload,
			"os_version":            starlark.String(database.OSVersion),
			"reference_count":       starlark.MakeInt(len(plan.References)),
			"sync_rounds":           starlark.MakeInt(catalog.catalog.Rounds),
			"target_build_info":     starlark.String(database.TargetBuildInfo),
			"target_os_version":     starlark.String(database.TargetOSVersion),
			"update_closure_count":  starlark.MakeInt(len(closure)),
			"update_revision_count": starlark.MakeInt(len(catalog.catalog.Revisions)),
			"update_stage_count":    starlark.MakeInt(len(updateStages)),
			"update_stages":         starlark.NewList(updateStageValues),
			"update_total_bytes":    starlark.MakeInt64(updateBytes),
		}), nil
	}
	metadataFile, err := openPayload(resources, rangePool, plan.Metadata, maximumEditionMetadata)
	if err != nil {
		return nil, fmt.Errorf("update_media: edition metadata: %w", err)
	}
	referenceReaders := make([]storage.Reader, 0, len(plan.References))
	for index, reference := range plan.References {
		file, err := openPayload(resources, rangePool, reference, maximumReferencePayload)
		if err != nil {
			return nil, fmt.Errorf("update_media: reference %d/%d %q: %w", index+1, len(plan.References), reference.Name, err)
		}
		referenceReaders = append(referenceReaders, file)
	}
	progress(fmt.Sprintf("update_media: opening base WIM with %d references after %s", len(referenceReaders), time.Since(mediaStarted).Round(time.Millisecond)))
	install, err := wim.OpenWithReferencesCache(metadataFile, referenceReaders, maximumWIMChunkCache)
	if err != nil {
		return nil, fmt.Errorf("update_media: open referenced edition ESD: %w", err)
	}
	progress(fmt.Sprintf("update_media: base WIM open after %s", time.Since(mediaStarted).Round(time.Millisecond)))
	if stateOnly {
		return starvalue.NewRecord(starlark.StringDict{
			"architecture": starlark.String(database.Architecture),
			"edition":      starlark.String(strings.ToLower(edition)),
			"install":      install,
			"kind":         starlark.String("windows-update-state"),
			"language":     starlark.String(strings.ToLower(language)),
		}), nil
	}
	started := time.Now()
	servicingCache, err := uup.NewStageMetadataCache(maximumServicingWIMCache)
	if err != nil {
		return nil, fmt.Errorf("update_media: servicing cache: %w", err)
	}
	assemblyPlanner, err := uup.NewAssemblyPlanner(install, "/image3")
	if err != nil {
		return nil, fmt.Errorf("update_media: initialize installed-OS package planner: %w", err)
	}
	var installedStages []*uup.CumulativeStage
	var installedStageMetadata []uup.UpdateStagePlan
	var assemblyPlans []uup.StageAssemblyPlan
	var servicingEffectPlans []uup.StageEffectPlan
	for _, updateStage := range updateStages {
		if updateStage.Scope != "installed-os" {
			continue
		}
		if installedStageLimit != 0 && len(installedStages) >= installedStageLimit {
			break
		}
		opened, metadata, err := openInstalledUpdateStages(resources, rangePool, updateContainers, servicingCache, []uup.UpdateStagePlan{updateStage}, func(plan uup.UpdateStagePlan, phase string) {
			progress(fmt.Sprintf("update_media: stage %s %s after %s", plan.FeatureID, phase, time.Since(started).Round(time.Millisecond)))
		})
		if err != nil {
			return nil, fmt.Errorf("update_media: open installed-OS update stage %q: %w", updateStage.FeatureID, err)
		}
		if len(opened) != 1 || len(metadata) != 1 {
			return nil, fmt.Errorf("update_media: stage %q did not open exactly once", updateStage.FeatureID)
		}
		assemblyPlan, err := assemblyPlanner.PlanStage(opened[0])
		if err != nil {
			return nil, fmt.Errorf("update_media: installed-OS stage %q package closure: %w", updateStage.FeatureID, err)
		}
		effectPlan, err := uup.PlanStageEffects(opened[0], assemblyPlan)
		if err != nil {
			return nil, fmt.Errorf("update_media: analyze installed-OS stage %q: %w", updateStage.FeatureID, err)
		}
		installedStages = append(installedStages, opened[0])
		installedStageMetadata = append(installedStageMetadata, metadata[0])
		assemblyPlans = append(assemblyPlans, assemblyPlan)
		servicingEffectPlans = append(servicingEffectPlans, effectPlan)
		progress(fmt.Sprintf("update_media: closed stage %s after %s (%d packages, %d components)", updateStage.FeatureID, time.Since(started).Round(time.Millisecond), len(assemblyPlan.Packages), len(assemblyPlan.Components)))
	}
	if len(assemblyPlans) != len(installedStageMetadata) || len(servicingEffectPlans) != len(assemblyPlans) {
		return nil, fmt.Errorf("update_media: planner returned %d assembly and %d effect stages for %d installed-OS updates", len(assemblyPlans), len(servicingEffectPlans), len(installedStageMetadata))
	}
	servicingPlanValues := make([]starlark.Value, 0, len(assemblyPlans))
	for index, assemblyPlan := range assemblyPlans {
		effectPlan := servicingEffectPlans[index]
		effects := effectPlan.Summary
		effectNames := make([]string, 0, len(effects.TopLevel))
		for name := range effects.TopLevel {
			effectNames = append(effectNames, name)
		}
		sort.Strings(effectNames)
		effectValues := make([]starlark.Value, 0, len(effectNames))
		for _, name := range effectNames {
			effectValues = append(effectValues, starvalue.NewRecord(starlark.StringDict{
				"count": starlark.MakeInt(effects.TopLevel[name]), "name": starlark.String(name),
			}))
		}
		payloadCount := 0
		if installedStages[index].Graph != nil {
			payloadCount = len(installedStages[index].Graph.Payloads)
		}
		servicingPlanValues = append(servicingPlanValues, starvalue.NewRecord(starlark.StringDict{
			"component_count":          starlark.MakeInt(len(assemblyPlan.Components)),
			"destination_roots":        stringCountDict(effects.DestinationRoots),
			"effect_types":             starlark.NewList(effectValues),
			"feature_id":               starlark.String(installedStageMetadata[index].FeatureID),
			"feature_type":             starlark.String(installedStageMetadata[index].FeatureType),
			"file_count":               starlark.MakeInt(effects.Files),
			"link_count":               starlark.MakeInt(effects.Links),
			"package_count":            starlark.MakeInt(len(assemblyPlan.Packages)),
			"payload_count":            starlark.MakeInt(payloadCount),
			"registry_roots":           stringCountDict(effects.RegistryRoots),
			"registry_count":           starlark.MakeInt(effects.RegistryValues),
			"registry_key_count":       starlark.MakeInt(effects.RegistryKeys),
			"registry_types":           stringCountDict(effects.RegistryTypes),
			"selected_payload_count":   starlark.MakeInt(effects.SelectedPayloads),
			"unselected_payload_count": starlark.MakeInt(effects.UnselectedPayloads),
		}))
	}
	validateServicing := starlark.NewBuiltin("validate_servicing", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		collectErrors := false
		errorLimit := 16
		var featureID string
		var sourceNames *starlark.List
		var onErrorValue starlark.Value = starlark.None
		if err := starlark.UnpackArgs("validate_servicing", args, kwargs, "collect_errors?", &collectErrors, "error_limit?", &errorLimit, "feature_id?", &featureID, "on_error?", &onErrorValue, "source_names?", &sourceNames); err != nil {
			return nil, err
		}
		var selectedNames []string
		if sourceNames != nil {
			for i := 0; i < sourceNames.Len(); i++ {
				name, ok := starlark.AsString(sourceNames.Index(i))
				if !ok || name == "" {
					return nil, fmt.Errorf("validate_servicing: source_names requires nonempty strings")
				}
				selectedNames = append(selectedNames, name)
			}
			if len(selectedNames) == 0 || featureID == "" {
				return nil, fmt.Errorf("validate_servicing: source_names requires names and feature_id")
			}
		}
		var onError starlark.Callable
		if onErrorValue != starlark.None {
			var ok bool
			onError, ok = onErrorValue.(starlark.Callable)
			if !ok || !collectErrors {
				return nil, fmt.Errorf("validate_servicing: on_error requires a callable and collect_errors=True")
			}
		}
		if errorLimit < 1 || errorLimit > 1000 {
			return nil, fmt.Errorf("validate_servicing: error_limit must be between 1 and 1000")
		}
		values := make([]starlark.Value, 0, len(servicingEffectPlans))
		for stageIndex, effectPlan := range servicingEffectPlans {
			if featureID != "" && !strings.EqualFold(featureID, installedStageMetadata[stageIndex].FeatureID) {
				continue
			}
			selectedFiles, err := selectServicingFiles(effectPlan.Files, selectedNames)
			if err != nil {
				return nil, fmt.Errorf("validate_servicing: %w", err)
			}
			var total int64
			failed := 0
			failures := make([]starlark.Value, 0)
			// Inspection must use the same source-local traversal as image
			// construction, without retaining every reconstructed file.
			for _, fileIndex := range installedStages[stageIndex].PlannedFileReadOrder(selectedFiles) {
				effect := selectedFiles[fileIndex]
				file, err := installedStages[stageIndex].OpenPlannedFile(effect)
				if err == nil {
					_, err = io.Copy(io.Discard, io.NewSectionReader(file, 0, file.Size()))
				}
				if err != nil {
					if !collectErrors {
						return nil, fmt.Errorf("validate_servicing: stage %q file %q: %w", installedStageMetadata[stageIndex].FeatureID, effect.SourceName, err)
					}
					failed++
					if len(failures) < errorLimit {
						failure := starvalue.NewRecord(starlark.StringDict{
							"name": starlark.String(effect.SourceName), "error": starlark.String(err.Error()),
							"feature_id": starlark.String(installedStageMetadata[stageIndex].FeatureID),
						})
						failures = append(failures, failure)
						if onError != nil {
							if _, err := starlark.Call(thread, onError, starlark.Tuple{failure}, nil); err != nil {
								return nil, err
							}
						}
					}
					continue
				}
				total += file.Size()
			}
			fields := starlark.StringDict{
				"bytes": starlark.MakeInt64(total), "feature_id": starlark.String(installedStageMetadata[stageIndex].FeatureID),
				"file_count": starlark.MakeInt(len(selectedFiles)),
			}
			if collectErrors {
				fields["ok"] = starlark.Bool(failed == 0)
				fields["verified_count"] = starlark.MakeInt(len(selectedFiles) - failed)
				fields["failed_count"] = starlark.MakeInt(failed)
				fields["errors"] = starlark.NewList(failures)
			}
			values = append(values, starvalue.NewRecord(fields))
		}
		if featureID != "" && len(values) == 0 {
			return nil, fmt.Errorf("validate_servicing: unknown installed-OS feature %q", featureID)
		}
		return starlark.NewList(values), nil
	})
	openServicingTarget := starlark.NewBuiltin("open_servicing_target", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var featureID, name string
		if err := starlark.UnpackArgs("open_servicing_target", args, kwargs, "feature_id", &featureID, "name", &name); err != nil {
			return nil, err
		}
		for index, stage := range installedStageMetadata {
			if strings.EqualFold(stage.FeatureID, featureID) {
				file, err := installedStages[index].OpenContentTarget(name)
				if err != nil {
					return nil, fmt.Errorf("open_servicing_target: %w", err)
				}
				return file.(starlark.Value), nil
			}
		}
		return nil, fmt.Errorf("open_servicing_target: unknown installed-OS feature %q", featureID)
	})
	diagnoseServicingTarget := starlark.NewBuiltin("diagnose_servicing_target", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var featureID, name string
		var expectedValue starlark.Value
		if err := starlark.UnpackArgs("diagnose_servicing_target", args, kwargs,
			"feature_id", &featureID, "name", &name, "expected", &expectedValue); err != nil {
			return nil, err
		}
		expected, ok := expectedValue.(storage.Reader)
		if !ok {
			return nil, fmt.Errorf("diagnose_servicing_target: expected got %s, want file", expectedValue.Type())
		}
		for index, stage := range installedStageMetadata {
			if !strings.EqualFold(stage.FeatureID, featureID) {
				continue
			}
			actual, applyErr := installedStages[index].DiagnoseContentTarget(name)
			if actual == nil {
				return nil, fmt.Errorf("diagnose_servicing_target: %w", applyErr)
			}
			diagnosis, err := compareServicingReaders(actual, expected)
			if err != nil {
				return nil, fmt.Errorf("diagnose_servicing_target: %w", err)
			}
			diagnosis["actual"] = actual.(starlark.Value)
			diagnosis["expected"] = expectedValue
			if applyErr != nil {
				diagnosis["apply_error"] = starlark.String(applyErr.Error())
			} else {
				diagnosis["apply_error"] = starlark.String("")
			}
			return starvalue.NewRecord(diagnosis), nil
		}
		return nil, fmt.Errorf("diagnose_servicing_target: unknown installed-OS feature %q", featureID)
	})
	servicingEffects := starlark.NewBuiltin("servicing_effects", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		includeFiles := true
		if err := starlark.UnpackArgs("servicing_effects", args, kwargs, "include_files?", &includeFiles); err != nil {
			return nil, err
		}
		verifiedCache, err := newVerifiedFileCache(maximumVerifiedFileCache)
		if err != nil {
			return nil, fmt.Errorf("servicing_effects: retained files: %w", err)
		}
		files := make([]starlark.Value, 0)
		registryKeys := make([]starlark.Value, 0)
		registryValues := make([]starlark.Value, 0)
		for stageIndex, effectPlan := range servicingEffectPlans {
			featureID := installedStageMetadata[stageIndex].FeatureID
			var stageFiles []starlark.Value
			var readOrder []int
			if includeFiles {
				stageFiles = make([]starlark.Value, len(effectPlan.Files))
				readOrder = installedStages[stageIndex].PlannedFileReadOrder(effectPlan.Files)
			}
			for _, fileIndex := range readOrder {
				effect := effectPlan.Files[fileIndex]
				file, err := installedStages[stageIndex].OpenPlannedFile(effect)
				if err != nil {
					return nil, fmt.Errorf("servicing_effects: stage %q file %q: %w", featureID, effect.SourceName, err)
				}
				// Every target is verified above. Retain its compressed immutable
				// bytes within the bounded cache, plus its recipe and expected hash.
				// Evicted files are reconstructed and reverified before publication;
				// cached files do not repeat construction work during boot.
				// Existing lazy archive members retain their native readers.
				if decoded, ok := file.(*starvalue.Bytes); ok {
					stage := installedStages[stageIndex]
					file, err = newVerifiedFile(verifiedCache, decoded.Name, decoded.Data, func() (storage.Reader, error) {
						return stage.OpenPlannedFile(effect)
					})
					if err != nil {
						return nil, fmt.Errorf("servicing_effects: retain verified file %q: %w", decoded.Name, err)
					}
				}
				value, ok := file.(starlark.Value)
				if !ok {
					return nil, fmt.Errorf("servicing_effects: stage %q file %q is not a Starlark file value", featureID, effect.SourceName)
				}
				destinations := make([]starlark.Value, len(effect.Destinations))
				for index, destination := range effect.Destinations {
					destinations[index] = starlark.String(destination)
				}
				stageFiles[fileIndex] = starvalue.NewRecord(starlark.StringDict{
					"architecture": starlark.String(effect.Architecture),
					"data":         value,
					"destinations": starlark.NewList(destinations),
					"feature_id":   starlark.String(featureID),
					"kind":         starlark.String(effect.Kind),
					"source_name":  starlark.String(effect.SourceName),
					"store_path":   starlark.String(effect.StorePath),
				})
			}
			files = append(files, stageFiles...)
			for _, effect := range effectPlan.RegistryKeys {
				registryKeys = append(registryKeys, starvalue.NewRecord(starlark.StringDict{
					"architecture": starlark.String(effect.Architecture),
					"feature_id":   starlark.String(featureID),
					"key":          starlark.String(effect.KeyName),
				}))
			}
			for _, effect := range effectPlan.RegistryValues {
				value := effect.Value
				registryValues = append(registryValues, starvalue.NewRecord(starlark.StringDict{
					"architecture":   starlark.String(effect.Architecture),
					"feature_id":     starlark.String(featureID),
					"key":            starlark.String(value.KeyName),
					"name":           starlark.String(value.Name),
					"type":           starlark.String(value.ValueType),
					"value":          starlark.String(value.Value),
					"operation_hint": starlark.String(value.OperationHint),
				}))
			}
		}
		return starvalue.NewRecord(starlark.StringDict{
			"files":           starlark.NewList(files),
			"registry_keys":   starlark.NewList(registryKeys),
			"registry_values": starlark.NewList(registryValues),
		}), nil
	})
	inspectFiles := starlark.NewBuiltin("inspect_servicing_files", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name, prefix string
		limit := 100
		if err := starlark.UnpackArgs("inspect_servicing_files", args, kwargs, "name?", &name, "destination_prefix?", &prefix, "limit?", &limit); err != nil {
			return nil, err
		}
		features := make([]string, len(installedStageMetadata))
		for index, stage := range installedStageMetadata {
			features[index] = stage.FeatureID
		}
		return inspectServicingFiles(servicingEffectPlans, features, name, prefix, limit)
	})
	if !indexOnly {
		if err := addCanonicalCabinetResources(resources, rangePool, plan.Cabinets, install); err != nil {
			return nil, fmt.Errorf("update_media: canonical cabinets: %w", err)
		}
	}
	bootsect := starlark.Value(starlark.None)
	if !indexOnly {
		bootsect, err = install.OpenFile("/image1/boot/bootsect.exe")
		if err != nil {
			return nil, fmt.Errorf("update_media: image 1 boot helper: %w", err)
		}
	}
	applicationPayloads := make([]starlark.Value, 0, len(plan.Applications))
	for _, file := range plan.Applications {
		applicationPayloads = append(applicationPayloads, starvalue.NewRecord(starlark.StringDict{
			"name": starlark.String(file.Name), "sha256": starlark.String(file.DigestSHA256), "size": starlark.MakeInt64(file.Size),
		}))
	}
	availablePayloads := make([]windowsupdate.File, len(files))
	copy(availablePayloads, files)
	sort.Slice(availablePayloads, func(i, j int) bool {
		return strings.ToLower(availablePayloads[i].Name) < strings.ToLower(availablePayloads[j].Name)
	})
	available := make([]starlark.Value, 0, len(availablePayloads))
	for _, file := range availablePayloads {
		available = append(available, starvalue.NewRecord(starlark.StringDict{
			"name":   starlark.String(file.Name),
			"sha256": starlark.String(file.DigestSHA256),
			"size":   starlark.MakeInt64(file.Size),
		}))
	}
	composition := compositionPackageRecords(database)
	features := compositionFeatureRecords(database)
	openComposition := starlark.NewBuiltin("open_composition", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("open_composition", args, kwargs, "name", &name); err != nil {
			return nil, err
		}
		database, err := compositionDatabaseFromCatalog(databases, name)
		if err != nil {
			return nil, fmt.Errorf("open_composition: %w", err)
		}
		return compositionDatabaseRecord(database), nil
	})
	openOfferPayload := starlark.NewBuiltin("open_payload", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("open_payload", args, kwargs, "name", &name); err != nil {
			return nil, err
		}
		file, err := findOfferFile(files, func(candidate string) bool {
			return strings.EqualFold(candidate, name)
		})
		if err != nil {
			return nil, fmt.Errorf("open_payload: %q: %w", name, err)
		}
		return openPayload(resources, rangePool, file, maximumReferencePayload)
	})
	return starvalue.NewRecord(starlark.StringDict{
		"architecture":              starlark.String(database.Architecture),
		"application_count":         starlark.MakeInt(len(plan.Applications)),
		"application_payloads":      starlark.NewList(applicationPayloads),
		"available_payloads":        starlark.NewList(available),
		"bootsect":                  bootsect,
		"build_info":                starlark.String(database.BuildInfo),
		"cabinet_count":             starlark.MakeInt(len(plan.Cabinets)),
		"composition_packages":      starlark.NewList(composition),
		"composition_features":      starlark.NewList(features),
		"composition_metadata":      starlark.NewList(compositionMetadata),
		"edition":                   starlark.String(strings.ToLower(edition)),
		"install":                   install,
		"index_only":                starlark.Bool(indexOnly),
		"kind":                      starlark.String("windows-update-media"),
		"language":                  starlark.String(strings.ToLower(language)),
		"offer_id":                  starlark.String(offer.ID),
		"offer_revision":            starlark.MakeInt(offer.Revision),
		"offer_title":               starlark.String(offer.Title),
		"sync_rounds":               starlark.MakeInt(catalog.catalog.Rounds),
		"update_revision_count":     starlark.MakeInt(len(catalog.catalog.Revisions)),
		"update_closure_count":      starlark.MakeInt(len(closure)),
		"update_stage_count":        starlark.MakeInt(len(updateStages)),
		"update_stages":             starlark.NewList(updateStageValues),
		"update_total_bytes":        starlark.MakeInt64(updateBytes),
		"os_version":                starlark.String(database.OSVersion),
		"target_build_info":         starlark.String(database.TargetBuildInfo),
		"target_os_version":         starlark.String(database.TargetOSVersion),
		"validate_servicing":        validateServicing,
		"open_composition":          openComposition,
		"open_payload":              openOfferPayload,
		"servicing_effects":         servicingEffects,
		"inspect_servicing_files":   inspectFiles,
		"open_servicing_target":     openServicingTarget,
		"diagnose_servicing_target": diagnoseServicingTarget,
		"reference_count":           starlark.MakeInt(len(plan.References)),
		"servicing_plan":            starlark.NewList(servicingPlanValues),
		"servicing_stage_count":     starlark.MakeInt(len(servicingPlanValues)),
		"total_bytes":               starlark.MakeInt64(plan.TotalSize),
	}), nil
}

func compareServicingReaders(actual, expected storage.Reader) (starlark.StringDict, error) {
	actualHash, expectedHash := sha256.New(), sha256.New()
	if _, err := io.Copy(actualHash, io.NewSectionReader(actual, 0, actual.Size())); err != nil {
		return nil, fmt.Errorf("hash actual: %w", err)
	}
	if _, err := io.Copy(expectedHash, io.NewSectionReader(expected, 0, expected.Size())); err != nil {
		return nil, fmt.Errorf("hash expected: %w", err)
	}
	limit := min(actual.Size(), expected.Size())
	const chunkSize = 64 << 10
	actualChunk, expectedChunk := make([]byte, chunkSize), make([]byte, chunkSize)
	var mismatchCount, firstMismatch, lastMismatch int64
	firstMismatch = -1
	type mismatchRun struct {
		start, end       int64
		actual, expected []byte
	}
	runs := make([]mismatchRun, 0, 32)
	var current *mismatchRun
	for offset := int64(0); offset < limit; {
		count := int(min(int64(chunkSize), limit-offset))
		if _, err := actual.ReadAt(actualChunk[:count], offset); err != nil {
			return nil, fmt.Errorf("read actual at %#x: %w", offset, err)
		}
		if _, err := expected.ReadAt(expectedChunk[:count], offset); err != nil {
			return nil, fmt.Errorf("read expected at %#x: %w", offset, err)
		}
		for index := range count {
			position := offset + int64(index)
			if actualChunk[index] == expectedChunk[index] {
				current = nil
				continue
			}
			mismatchCount++
			lastMismatch = position
			if firstMismatch < 0 {
				firstMismatch = position
			}
			if current == nil && len(runs) < cap(runs) {
				runs = append(runs, mismatchRun{start: position, end: position})
				current = &runs[len(runs)-1]
			}
			if current != nil {
				current.end = position + 1
				if len(current.actual) < 16 {
					current.actual = append(current.actual, actualChunk[index])
					current.expected = append(current.expected, expectedChunk[index])
				}
			}
		}
		offset += int64(count)
	}
	if actual.Size() != expected.Size() {
		mismatchCount += max(actual.Size(), expected.Size()) - limit
		if firstMismatch < 0 {
			firstMismatch = limit
		}
		lastMismatch = max(actual.Size(), expected.Size()) - 1
	}
	runValues := make([]starlark.Value, len(runs))
	for index, run := range runs {
		runValues[index] = starvalue.NewRecord(starlark.StringDict{
			"actual": starlark.String(hex.EncodeToString(run.actual)), "end": starlark.MakeInt64(run.end),
			"expected": starlark.String(hex.EncodeToString(run.expected)), "start": starlark.MakeInt64(run.start),
		})
	}
	return starlark.StringDict{
		"actual_sha256": starlark.String(hex.EncodeToString(actualHash.Sum(nil))),
		"actual_size":   starlark.MakeInt64(actual.Size()), "expected_sha256": starlark.String(hex.EncodeToString(expectedHash.Sum(nil))),
		"expected_size": starlark.MakeInt64(expected.Size()), "first_mismatch": starlark.MakeInt64(firstMismatch),
		"last_mismatch": starlark.MakeInt64(lastMismatch), "mismatch_count": starlark.MakeInt64(mismatchCount),
		"mismatch_runs": starlark.NewList(runValues), "matches": starlark.Bool(mismatchCount == 0),
	}, nil
}

func stringCountDict(counts map[string]int) *starlark.Dict {
	result := starlark.NewDict(len(counts))
	for name, count := range counts {
		_ = result.SetKey(starlark.String(name), starlark.MakeInt(count))
	}
	return result
}

func updateContainerKey(file windowsupdate.File) string {
	return strings.ToLower(file.DigestSHA256) + "\x00" + strings.ToLower(file.Name)
}

// indexUpdatePayloadSources exposes MSU members as logical payloads while
// retaining the offered MSU as their physical, signed download container.
// CAB headers are read through the bounded byte channel; no member is
// extracted or written to the host.
type indexedUpdateContainer struct {
	cab *cab.Archive
	wim *wim.Archive
}

func (c *indexedUpdateContainer) open(name string) (storage.Reader, error) {
	if c == nil {
		return nil, fmt.Errorf("nil update container")
	}
	if c.cab != nil {
		return c.cab.Lookup(name)
	}
	if c.wim != nil {
		return c.wim.OpenFile(name)
	}
	return nil, fmt.Errorf("update container has no archive")
}

func indexUpdatePayloadSources(resources *lifecycle.Resources, rangePool *storagenative.HTTPRangePool, files []windowsupdate.File) ([]uup.UpdatePayloadSource, map[string]*indexedUpdateContainer, error) {
	sources := make([]uup.UpdatePayloadSource, 0, len(files))
	containers := make(map[string]*indexedUpdateContainer)
	for _, file := range files {
		if file.Name != "" && file.Size >= 0 {
			sources = append(sources, uup.UpdatePayloadSource{Container: file, Name: file.Name, Size: file.Size})
		}
		if !strings.EqualFold(path.Ext(file.Name), ".msu") {
			continue
		}
		reader, err := openPayload(resources, rangePool, file, maximumReferencePayload)
		if err != nil {
			return nil, nil, fmt.Errorf("open MSU %q: %w", file.Name, err)
		}
		signature := make([]byte, 8)
		n, readErr := reader.ReadAt(signature, 0)
		if readErr != nil && readErr != io.EOF {
			return nil, nil, fmt.Errorf("read MSU %q signature: %w", file.Name, readErr)
		}
		key := updateContainerKey(file)
		if _, exists := containers[key]; exists {
			return nil, nil, fmt.Errorf("duplicate MSU container identity %q", file.Name)
		}
		switch string(signature[:n]) {
		case "MSCF\x00\x00\x00\x00":
			archive, err := cab.Open(reader, false)
			if err != nil {
				return nil, nil, fmt.Errorf("index CAB MSU %q: %w", file.Name, err)
			}
			containers[key] = &indexedUpdateContainer{cab: archive}
			for _, member := range archive.Files() {
				sources = append(sources, uup.UpdatePayloadSource{Container: file, Member: member.Name, Name: path.Base(member.Name), Size: member.Size})
			}
		case "MSWIM\x00\x00\x00":
			archive, err := wim.OpenWithCache(reader, bytecache.New(64<<20), 1)
			if err != nil {
				return nil, nil, fmt.Errorf("index WIM MSU %q: %w", file.Name, err)
			}
			containers[key] = &indexedUpdateContainer{wim: archive}
			if err := archive.Walk("/image1", func(member wim.EntryInfo) error {
				if member.Directory {
					return nil
				}
				sources = append(sources, uup.UpdatePayloadSource{Container: file, Member: member.Path, Name: path.Base(member.Path), Size: member.Size})
				return nil
			}); err != nil {
				return nil, nil, fmt.Errorf("walk WIM MSU %q: %w", file.Name, err)
			}
		default:
			return nil, nil, fmt.Errorf("MSU %q has unsupported signature %x", file.Name, signature[:n])
		}
		if len(sources) > 65536 {
			return nil, nil, fmt.Errorf("update payload catalog exceeds 65536 entries")
		}
	}
	return sources, containers, nil
}

func openUpdatePayload(resources *lifecycle.Resources, rangePool *storagenative.HTTPRangePool, containers map[string]*indexedUpdateContainer, payload uup.UpdatePayload, maximum int64) (storage.Reader, error) {
	if payload.Source.Size < 0 || payload.Source.Size > maximum {
		return nil, fmt.Errorf("payload %q size %d exceeds %d-byte bound", payload.Source.Name, payload.Source.Size, maximum)
	}
	if payload.Source.Member == "" {
		return openPayload(resources, rangePool, payload.Source.Container, maximum)
	}
	archive := containers[updateContainerKey(payload.Source.Container)]
	if archive == nil {
		return nil, fmt.Errorf("payload %q refers to unindexed container %q", payload.Source.Name, payload.Source.Container.Name)
	}
	member, err := archive.open(payload.Source.Member)
	if err != nil {
		return nil, fmt.Errorf("container %q member %q: %w", payload.Source.Container.Name, payload.Source.Member, err)
	}
	if member.Size() != payload.Source.Size {
		return nil, fmt.Errorf("container %q member %q changed size from %d to %d", payload.Source.Container.Name, payload.Source.Member, payload.Source.Size, member.Size())
	}
	return member, nil
}

func openInstalledUpdateStages(resources *lifecycle.Resources, rangePool *storagenative.HTTPRangePool, containers map[string]*indexedUpdateContainer, cache *uup.StageMetadataCache, plans []uup.UpdateStagePlan, observe func(uup.UpdateStagePlan, string)) ([]*uup.CumulativeStage, []uup.UpdateStagePlan, error) {
	var stages []*uup.CumulativeStage
	var selected []uup.UpdateStagePlan
	for _, plan := range plans {
		if plan.Scope != "installed-os" {
			continue
		}
		if observe != nil {
			observe(plan, "begin")
		}
		byRole := make(map[string][]uup.UpdatePayload)
		for _, payload := range plan.Payloads {
			if !payload.Selected {
				continue
			}
			byRole[payload.Role] = append(byRole[payload.Role], payload)
		}
		var stage *uup.CumulativeStage
		if len(byRole["express-metadata"]) != 0 || len(byRole["express-psf"]) != 0 {
			if len(byRole["express-metadata"]) == 0 || len(byRole["express-psf"]) != 1 {
				return nil, nil, fmt.Errorf("feature %q express payload set is not yet composable: metadata %v, PSF %v", plan.FeatureID, updatePayloadNames(byRole["express-metadata"]), updatePayloadNames(byRole["express-psf"]))
			}
			psf := byRole["express-psf"][0]
			metadataNames := make([]string, 0, len(byRole["express-metadata"]))
			metadataFiles := make([]storage.Reader, 0, len(byRole["express-metadata"]))
			for _, metadata := range byRole["express-metadata"] {
				metadataFile, err := openUpdatePayload(resources, rangePool, containers, metadata, maximumEditionMetadata)
				if err != nil {
					return nil, nil, fmt.Errorf("feature %q metadata %q: %w", plan.FeatureID, metadata.Source.Name, err)
				}
				metadataNames = append(metadataNames, metadata.Source.Name)
				metadataFiles = append(metadataFiles, metadataFile)
			}
			psfFile, err := openUpdatePayload(resources, rangePool, containers, psf, maximumReferencePayload)
			if err != nil {
				return nil, nil, fmt.Errorf("feature %q PSF: %w", plan.FeatureID, err)
			}
			if observe != nil {
				observe(plan, "payloads-open")
			}
			stage, err = uup.OpenCumulativeStagePayloadsCache(metadataNames, metadataFiles, psf.Source.Name, psfFile, cache)
			if err != nil {
				return nil, nil, fmt.Errorf("feature %q express stage: %w", plan.FeatureID, err)
			}
		} else {
			canonical := byRole["canonical-cab"]
			if len(canonical) == 0 {
				canonical = byRole["psfx-cab"]
			}
			if len(canonical) != 1 {
				return nil, nil, fmt.Errorf("feature %q needs one canonical update cabinet, got %d", plan.FeatureID, len(canonical))
			}
			file, err := openUpdatePayload(resources, rangePool, containers, canonical[0], maximumReferencePayload)
			if err != nil {
				return nil, nil, fmt.Errorf("feature %q cabinet: %w", plan.FeatureID, err)
			}
			if observe != nil {
				observe(plan, "payload-open")
			}
			stage, err = uup.OpenCanonicalStage(canonical[0].Source.Name, file)
			if err != nil {
				return nil, nil, fmt.Errorf("feature %q canonical stage: %w", plan.FeatureID, err)
			}
		}
		stages = append(stages, stage)
		selected = append(selected, plan)
		if observe != nil {
			observe(plan, "open")
		}
	}
	return stages, selected, nil
}

func updatePayloadNames(payloads []uup.UpdatePayload) []string {
	result := make([]string, len(payloads))
	for index, payload := range payloads {
		result[index] = payload.Source.Name
	}
	sort.Strings(result)
	return result
}

func addCanonicalCabinetResources(resources *lifecycle.Resources, rangePool *storagenative.HTTPRangePool, cabinets []windowsupdate.File, install *wim.Archive) error {
	missing, err := install.MissingResourceHashes()
	if err != nil {
		return fmt.Errorf("enumerate missing WIM resources: %w", err)
	}
	wanted := make(map[[20]byte]struct{}, len(missing))
	for _, digest := range missing {
		wanted[digest] = struct{}{}
	}
	retainedFiles, err := newRetainedFileStore()
	if err != nil {
		return err
	}
	type cabinetResult struct {
		index int
		name  string
		sha1  [20]byte
		data  []byte
		ack   chan struct{}
		done  bool
		err   error
	}
	workerCount := min(len(cabinets), maximumCabinetWorkers, runtime.GOMAXPROCS(0))
	jobs := make(chan int, len(cabinets))
	results := make(chan cabinetResult)
	folderBudget := newSharedByteBudget(maximumCanonicalFolder)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for cabinetIndex := range jobs {
				payload := cabinets[cabinetIndex]
				file, err := openPayload(resources, rangePool, payload, maximumReferencePayload)
				if err != nil {
					results <- cabinetResult{index: cabinetIndex, done: true, err: fmt.Errorf("cabinet %d/%d %q: %w", cabinetIndex+1, len(cabinets), payload.Name, err)}
					continue
				}
				archive, err := cab.Open(file, false)
				if err != nil {
					results <- cabinetResult{index: cabinetIndex, done: true, err: fmt.Errorf("open %q: %w", payload.Name, err)}
					continue
				}
				err = archive.VisitResourcesBySHA1(wanted, maximumCanonicalFolder, folderBudget, func(name string, digest [20]byte, data []byte) error {
					ack := make(chan struct{})
					results <- cabinetResult{index: cabinetIndex, name: name, sha1: digest, data: data, ack: ack}
					<-ack
					return nil
				})
				if err != nil {
					err = fmt.Errorf("resolve %q: %w", payload.Name, err)
				}
				results <- cabinetResult{index: cabinetIndex, done: true, err: err}
			}
		}()
	}
	for index := range cabinets {
		jobs <- index
	}
	close(jobs)
	go func() {
		workers.Wait()
		close(results)
	}()

	var external []wim.ExternalResource
	var retained int64
	found := make(map[[20]byte]struct{}, len(wanted))
	errorsByCabinet := make([]error, len(cabinets))
	var resourceLimitErr error
	for result := range results {
		if result.done {
			if result.err != nil {
				errorsByCabinet[result.index] = result.err
			}
			continue
		}
		payload := cabinets[result.index]
		if _, exists := found[result.sha1]; !exists {
			if retained+int64(len(result.data)) > maximumCanonicalResources {
				resourceLimitErr = fmt.Errorf("selected canonical resources exceed %d-byte bound", maximumCanonicalResources)
			} else {
				data, err := retainedFiles.pack(payload.Name+result.name, result.data)
				if err != nil {
					resourceLimitErr = fmt.Errorf("retain canonical resource %q: %w", result.name, err)
				} else {
					external = append(external, wim.ExternalResource{SHA1: result.sha1, File: data})
					retained += int64(len(result.data))
					found[result.sha1] = struct{}{}
				}
			}
		}
		close(result.ack)
	}
	for _, err := range errorsByCabinet {
		if err != nil {
			return err
		}
	}
	if resourceLimitErr != nil {
		return resourceLimitErr
	}
	if len(found) != len(wanted) {
		return fmt.Errorf("resolved %d of %d missing canonical WIM resources", len(found), len(wanted))
	}
	if err := install.AddExternalResources(external); err != nil {
		return err
	}
	return nil
}

func compositionDatabaseRecord(database *uup.Database) starlark.Value {
	tags := make([]starlark.Value, 0, len(database.Tags))
	for _, tag := range database.Tags {
		tags = append(tags, starvalue.NewRecord(starlark.StringDict{
			"name":  starlark.String(tag.Name),
			"value": starlark.String(tag.Value),
		}))
	}
	return starvalue.NewRecord(starlark.StringDict{
		"architecture":      starlark.String(database.Architecture),
		"build_info":        starlark.String(database.BuildInfo),
		"features":          starlark.NewList(compositionFeatureRecords(database)),
		"name":              starlark.String(database.Name),
		"source":            starlark.String(database.Source),
		"os_version":        starlark.String(database.OSVersion),
		"packages":          starlark.NewList(compositionPackageRecords(database)),
		"tags":              starlark.NewList(tags),
		"target_build_info": starlark.String(database.TargetBuildInfo),
		"target_os_version": starlark.String(database.TargetOSVersion),
		"type":              starlark.String(database.Type),
	})
}

func compositionCatalogRecords(databases []*uup.Database) []starlark.Value {
	ordered := append([]*uup.Database(nil), databases...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i] == nil {
			return ordered[j] != nil
		}
		if ordered[j] == nil {
			return false
		}
		return strings.ToLower(ordered[i].Source) < strings.ToLower(ordered[j].Source)
	})
	values := make([]starlark.Value, 0, len(ordered))
	for _, database := range ordered {
		if database == nil {
			continue
		}
		values = append(values, starvalue.NewRecord(starlark.StringDict{
			"feature_count":     starlark.MakeInt(len(database.Features)),
			"name":              starlark.String(database.Name),
			"os_version":        starlark.String(database.OSVersion),
			"package_count":     starlark.MakeInt(len(database.Packages)),
			"source":            starlark.String(database.Source),
			"target_os_version": starlark.String(database.TargetOSVersion),
			"type":              starlark.String(database.Type),
		}))
	}
	return values
}

func compositionFeatureRecords(database *uup.Database) []starlark.Value {
	values := make([]starlark.Value, 0, len(database.Features))
	for _, feature := range database.Features {
		dependencies := make([]starlark.Value, 0, len(feature.Dependencies))
		for _, dependency := range feature.Dependencies {
			dependencies = append(dependencies, starvalue.NewRecord(starlark.StringDict{
				"group":       starlark.String(dependency.Group),
				"id":          starlark.String(dependency.ID),
				"manifest_id": starlark.String(dependency.ManifestID),
				"type":        starlark.String(dependency.Type),
			}))
		}
		values = append(values, starvalue.NewRecord(starlark.StringDict{
			"dependencies": starlark.NewList(dependencies),
			"group":        starlark.String(feature.Group),
			"id":           starlark.String(feature.ID),
			"manifest_id":  starlark.String(feature.ManifestID),
			"type":         starlark.String(feature.Type),
		}))
	}
	return values
}

func compositionPackageRecords(database *uup.Database) []starlark.Value {
	packages := append([]uup.Package(nil), database.Packages...)
	for _, feature := range database.Features {
		packages = append(packages, feature.Packages...)
	}
	sort.Slice(packages, func(i, j int) bool {
		return strings.ToLower(packages[i].ID) < strings.ToLower(packages[j].ID)
	})
	values := make([]starlark.Value, 0, len(packages))
	for _, pack := range packages {
		payloads := make([]starlark.Value, 0, len(pack.Payload))
		for _, payload := range pack.Payload {
			payloads = append(payloads, starvalue.NewRecord(starlark.StringDict{
				"hash": starlark.String(payload.Hash),
				"path": starlark.String(payload.Path),
				"size": starlark.MakeInt64(payload.Size),
				"type": starlark.String(payload.Type),
			}))
		}
		values = append(values, starvalue.NewRecord(starlark.StringDict{
			"id":       starlark.String(pack.ID),
			"payloads": starlark.NewList(payloads),
			"type":     starlark.String(pack.Type),
		}))
	}
	return values
}

func findOfferFile(files []windowsupdate.File, match func(string) bool) (windowsupdate.File, error) {
	var selected *windowsupdate.File
	for index := range files {
		file := &files[index]
		if !match(strings.ToLower(file.Name)) {
			continue
		}
		if selected == nil {
			selected = file
			continue
		}
		if selected.Size != file.Size || !strings.EqualFold(selected.DigestSHA256, file.DigestSHA256) || !strings.EqualFold(selected.Name, file.Name) {
			return windowsupdate.File{}, fmt.Errorf("offer has ambiguous required payload %q and %q", selected.Name, file.Name)
		}
	}
	if selected == nil {
		return windowsupdate.File{}, fmt.Errorf("offer has no required payload")
	}
	return *selected, nil
}

func openPayload(resources *lifecycle.Resources, rangePool *storagenative.HTTPRangePool, file windowsupdate.File, maximum int64) (*storagenative.HTTPRangeFile, error) {
	if file.DownloadURL == "" || file.DigestSHA256 == "" || file.Size <= 0 {
		return nil, fmt.Errorf("payload %q lacks a URL, SHA-256 digest, or positive size", file.Name)
	}
	if file.Size > maximum {
		return nil, fmt.Errorf("payload %q size %d exceeds %d-byte bound", file.Name, file.Size, maximum)
	}
	result, err := rangePool.OpenSHA256(resources.Context(), file.Name, []string{file.DownloadURL}, file.Size, file.DigestSHA256)
	if err != nil {
		return nil, err
	}
	if _, err := resources.Add(result); err != nil {
		_ = result.Close()
		return nil, fmt.Errorf("register payload: %w", err)
	}
	return result, nil
}

const (
	maximumCompositionDepth     = 4
	maximumCompositionDocuments = 4096
	maximumCompositionXML       = int64(16 << 20)
)

// compositionDatabases walks the composition metadata containers themselves.
// LCU metadata is carried as direct CompDB XML in an outer.AggregatedMetadata
// cabinet, while edition metadata is normally a CompDB XML cabinet. Treating
// only top-level *.xml.cab members as the catalog silently loses the LCU/SSU
// dependency graph.
func compositionDatabases(aggregated *cab.Archive) ([]*uup.Database, error) {
	if aggregated == nil {
		return nil, fmt.Errorf("composition catalog requires an archive")
	}
	var result []*uup.Database
	var walk func(*cab.Archive, string, int) error
	walk = func(archive *cab.Archive, prefix string, depth int) error {
		if depth > maximumCompositionDepth {
			return fmt.Errorf("composition container %q exceeds nesting depth %d", prefix, maximumCompositionDepth)
		}
		for _, member := range archive.Files() {
			base := strings.ToLower(path.Base(member.Name))
			source := prefix + member.Name
			switch {
			case strings.Contains(base, "compdb") && strings.HasSuffix(base, ".xml.cab"):
				entry, err := archive.Lookup(member.Name)
				if err != nil {
					return err
				}
				inner, err := cab.Open(entry, false)
				if err != nil {
					return fmt.Errorf("open CompDB cabinet %q: %w", source, err)
				}
				database, err := parseCompDBCabinet(inner, source)
				if err != nil {
					return err
				}
				result = append(result, database)
			case strings.Contains(base, "compdb") && strings.HasSuffix(base, ".xml"):
				database, err := parseCompDBMember(archive, member.Name, source)
				if err != nil {
					return err
				}
				result = append(result, database)
			case strings.HasPrefix(base, "outer.aggregatedmetadata_") && strings.HasSuffix(base, ".cab"):
				entry, err := archive.Lookup(member.Name)
				if err != nil {
					return err
				}
				inner, err := cab.Open(entry, false)
				if err != nil {
					return fmt.Errorf("open nested composition cabinet %q: %w", source, err)
				}
				if err := walk(inner, source+"!", depth+1); err != nil {
					return err
				}
			}
			if len(result) > maximumCompositionDocuments {
				return fmt.Errorf("composition catalog exceeds %d documents", maximumCompositionDocuments)
			}
		}
		return nil
	}
	if err := walk(aggregated, "", 0); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("composition catalog contains no CompDB documents")
	}
	return result, nil
}

func parseCompDBCabinet(archive *cab.Archive, source string) (*uup.Database, error) {
	var candidates []string
	for _, member := range archive.Files() {
		if strings.HasSuffix(strings.ToLower(member.Name), ".xml") {
			candidates = append(candidates, member.Name)
		}
	}
	if len(candidates) != 1 {
		return nil, fmt.Errorf("CompDB cabinet %q contains %d XML documents", source, len(candidates))
	}
	return parseCompDBMember(archive, candidates[0], source)
}

func parseCompDBMember(archive *cab.Archive, memberName, source string) (*uup.Database, error) {
	entry, err := archive.Lookup(memberName)
	if err != nil {
		return nil, err
	}
	if entry.Size() < 0 || entry.Size() > maximumCompositionXML {
		return nil, fmt.Errorf("CompDB %q size %d exceeds %d-byte bound", source, entry.Size(), maximumCompositionXML)
	}
	data, err := entry.Bytes()
	if err != nil {
		return nil, err
	}
	database, err := uup.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse CompDB %q member %q: %w", source, memberName, err)
	}
	database.Source = source
	if database.Name == "" {
		database.Name = path.Base(source)
	}
	return database, nil
}

func compositionDatabaseFromCatalog(databases []*uup.Database, name string) (*uup.Database, error) {
	wanted := strings.ToLower(strings.TrimSpace(name))
	var matches []*uup.Database
	for _, database := range databases {
		if database == nil {
			continue
		}
		if strings.EqualFold(database.Source, wanted) || strings.EqualFold(path.Base(database.Source), path.Base(wanted)) || strings.EqualFold(database.Name, wanted) {
			matches = append(matches, database)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("composition catalog has %d databases matching %q", len(matches), name)
	}
	return matches[0], nil
}
