package uup

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/registry"
)

type CBSResidentSourceRow struct {
	Identity []byte
	Values   []registry.Value
}

// ReadCBSResidentSources returns validated native p!/i!/s! rows in hive order.
// The rows describe immutable baseline declarations, without applying changes.
func ReadCBSResidentSources(ctx context.Context, hive *registry.Hive, cache storage.DerivedCache) ([]CBSResidentSourceRow, error) {
	build := func() ([]CBSResidentSourceRow, error) { return readCBSResidentSources(hive) }
	if cache == nil {
		return build()
	}
	digest, ok := hive.VerifiedSHA256()
	if !ok {
		return nil, fmt.Errorf("CSI source inventory requires an immutable COMPONENTS hive")
	}
	key := storage.DerivedKey("windows.csi.resident-sources/v1", digest)
	var rows []CBSResidentSourceRow
	var readErr error
	record, err := cache.GetOrBuild(ctx, key, maximumAssemblyRecord, func() ([]byte, error) {
		rows, readErr = build()
		if readErr != nil {
			return nil, readErr
		}
		return packCBSRecord(reflect.ValueOf(rows))
	})
	if rows != nil || readErr != nil {
		return rows, readErr
	}
	if err == nil && unpackCBSRecord(record, reflect.ValueOf(&rows).Elem()) == nil {
		return rows, nil
	}
	return build()
}

func readCBSResidentSources(hive *registry.Hive) ([]CBSResidentSourceRow, error) {
	root, err := hive.LookupParts([]string{"CanonicalData", "Deployments"})
	if err != nil {
		return nil, err
	}
	deployments, err := hive.ReadSubkeys(root)
	if err != nil {
		return nil, err
	}
	if len(deployments) > 1<<20 {
		return nil, fmt.Errorf("resident CSI deployment count exceeds bound")
	}
	rows := make([]CBSResidentSourceRow, 0, len(deployments))
	seen := make(map[string]bool, len(deployments))
	totalBytes := 0
	for _, deployment := range deployments {
		cells, err := hive.ValueCells(deployment)
		if err != nil {
			return nil, err
		}
		var row CBSResidentSourceRow
		for _, cell := range cells {
			value, err := hive.ReadValue(cell)
			if err != nil {
				return nil, err
			}
			if value.Name == "appid" {
				if len(value.Data) > 64<<10 {
					return nil, fmt.Errorf("resident CSI deployment identity exceeds bound")
				}
				row.Identity = value.Data
				totalBytes += len(value.Data)
				continue
			}
			switch strings.ToLower(value.Name[:min(2, len(value.Name))]) {
			case "p!", "i!", "s!":
				if len(value.Name) > 256 || len(value.Data) > 64<<10 {
					return nil, fmt.Errorf("CSI source value exceeds bound")
				}
				row.Values = append(row.Values, value)
				totalBytes += len(value.Name) + len(value.Data)
			}
		}
		if totalBytes > 256<<20 {
			return nil, fmt.Errorf("resident CSI sources exceed byte bound")
		}
		identity := strings.ToLower(string(row.Identity))
		if row.Identity == nil || seen[identity] {
			return nil, fmt.Errorf("missing or duplicate exact CSI source deployment")
		}
		seen[identity] = true
		if _, err := PlanCSISourceWrites(row.Values, nil); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}
