package dmr

import (
	"fmt"
	"strings"
)

// EncodeMissingFileResourceReference implements the manifest-file fallback
// after a Files-subtree lookup returned ERROR_MRM_NAMED_RESOURCE_NOT_FOUND or
// ERROR_MRM_MAP_NOT_FOUND. The caller must establish that lookup result first.
// This is not a general path join, URI resolver, or missing-PRI fallback.
func EncodeMissingFileResourceReference(packagePath, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("dmr: missing-file fallback requires a nonempty lookup name")
	}
	// ConcatPathElement trims only the requested separator, then the caller
	// normalizes forward slashes. Do not clean dot components or parse URLs.
	head := strings.TrimRight(packagePath, `\`)
	tail := strings.TrimLeft(value, `\`)
	if head != "" {
		head += `\`
	}
	return EncodeLiteralResourceReference(strings.ReplaceAll(head+tail, "/", `\`))
}
