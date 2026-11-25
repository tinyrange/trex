package vmm

import (
	"context"
	"github.com/tinyrange/trex/block"
)

// MediaReplacer replaces read-only distribution media without materializing a
// source file or exposing backend paths. An error after submission may leave
// the drive empty or changed; callers must inspect state, never blindly retry.
type MediaReplacer interface {
	ReplaceMedia(context.Context, string, block.Device) error
}
