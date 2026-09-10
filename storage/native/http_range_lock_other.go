//go:build !unix && !windows

package native

import (
	"context"
	"fmt"
	"os"
)

func lockHTTPRangeCache(context.Context, string) (*os.File, error) {
	return nil, fmt.Errorf("persistent native HTTP cache locking is unavailable on this platform")
}
