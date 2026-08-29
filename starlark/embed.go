// Package starlark provides the embedded trex standard library.
package starlark

import "embed"

// StandardLibrary contains all shipped .star modules.
//
//go:embed stdlib
var StandardLibrary embed.FS
