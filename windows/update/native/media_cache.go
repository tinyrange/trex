package native

import (
	"fmt"
	"os"
	"path/filepath"
)

// mediaCacheDirectory preserves the historical default for library callers.
// An explicit path belongs to this request, never to process-wide environment.
func mediaCacheDirectory(directory string) (string, error) {
	if directory != "" {
		return filepath.Abs(directory)
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("update_media: locate persistent UUP cache: %w", err)
	}
	return filepath.Join(root, "tinyrangex", "uup"), nil
}
