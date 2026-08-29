package qemu

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func unsupportedVMM(operation string) error {
	return &vmmapi.Error{Code: vmmapi.ErrorUnsupported, Message: operation + " is unsupported"}
}

func operationContext(timeout float64) (context.Context, context.CancelFunc, error) {
	if timeout <= 0 || timeout > 86400 {
		return nil, nil, fmt.Errorf("invalid timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*float64(time.Second)))
	return ctx, cancel, nil
}

func normalizedCapabilities(capabilities []string) []string {
	seen := make(map[string]bool, len(capabilities))
	result := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		capability = strings.TrimSpace(strings.ToLower(capability))
		if capability != "" && !seen[capability] {
			seen[capability] = true
			result = append(result, capability)
		}
	}
	sort.Strings(result)
	return result
}

func stringListValue(values []string) *starlark.List {
	items := make([]starlark.Value, len(values))
	for index, value := range values {
		items[index] = starlark.String(value)
	}
	return starlark.NewList(items)
}

func vmmResultValue(result vmmapi.Result) starlark.Value {
	return starvalue.NewRecord(starlark.StringDict{
		"backend": starlark.String(result.Backend), "clean": starlark.Bool(result.Clean),
		"detail": starlark.String(result.Detail), "reason": starlark.String(result.Reason),
	})
}
