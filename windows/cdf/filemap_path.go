package cdf

import (
	"fmt"
	"strings"
)

// FileMapPath computes the metadata emitted by WCP AdjustMapParentDirectory.
// Inputs are canonical ASCII image paths, not host paths. volume is an explicit
// drive designator (for example C:); it is only emitted for the image root.
// Unlike FileMapName, native metadata uses a literal case-insensitive Windows
// prefix, including when the following character is not a separator.
func FileMapPath(imagePath, windowsRoot, volume string) (string, uint32, error) {
	if err := validateFileMapImagePath(imagePath); err != nil {
		return "", 0, err
	}
	if err := validateFileMapImagePath(windowsRoot); err != nil {
		return "", 0, err
	}
	if windowsRoot == "/" {
		return "", 0, fmt.Errorf("Windows root cannot be the image drive root")
	}
	if len(volume) != 2 || volume[1] != ':' || !((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
		return "", 0, fmt.Errorf("FileMap volume must be an ASCII drive designator")
	}
	if imagePath == "/" {
		return `\??\` + volume, 0, nil
	}
	if len(imagePath) >= len(windowsRoot) && strings.EqualFold(imagePath[:len(windowsRoot)], windowsRoot) {
		return strings.ReplaceAll(strings.TrimPrefix(imagePath[len(windowsRoot):], "/"), "/", `\`), 1, nil
	}
	return strings.ReplaceAll(imagePath[1:], "/", `\`), 2, nil
}
