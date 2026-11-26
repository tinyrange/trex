package uup

import (
	"context"
	"crypto/sha256"
	"reflect"

	"github.com/tinyrange/trex/storage"
)

// CBSPhasePlan captures admission and deployment declarations. It contains
// neither the applied registry nor a candidate filesystem or payload readers.
type CBSPhasePlan struct {
	StagePackages []string
	Actions       []CBSDeploymentAction
	Executions    []CBSOrdinaryExecution
	Admissions    int
	PackageNames  map[string]string
}

func LoadCBSPhasePlan(ctx context.Context, cache storage.DerivedCache, inputs [sha256.Size]byte, build func() (*CBSPhasePlan, error)) (*CBSPhasePlan, error) {
	key := storage.DerivedKey("windows.cbs.package-phases/v2", inputs)
	var built *CBSPhasePlan
	var buildErr error
	data, err := cache.GetOrBuild(ctx, key, maximumAssemblyRecord, func() ([]byte, error) {
		built, buildErr = build()
		if buildErr != nil {
			return nil, buildErr
		}
		return packCBSRecord(reflect.ValueOf(*built))
	})
	if built != nil || buildErr != nil {
		return built, buildErr
	}
	if err == nil {
		var plan CBSPhasePlan
		if err := unpackCBSRecord(data, reflect.ValueOf(&plan).Elem()); err == nil {
			return &plan, nil
		}
	}
	return build()
}
