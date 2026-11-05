package native

import (
	"fmt"
	"regexp"

	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

var imageRootPattern = regexp.MustCompile(`^/image[1-9][0-9]*$`)

// externalServicingBase validates the explicit image boundary before any network
// access. A supplied image is never silently replaced with downloaded media.
func externalServicingBase(base starlark.Value, image string, bootsect starlark.Value) (*wim.Archive, error) {
	if base == starlark.None {
		if image != "" || bootsect != starlark.None {
			return nil, fmt.Errorf("update_media: image and bootsect require base")
		}
		return nil, nil
	}
	archive, ok := base.(*wim.Archive)
	if !ok {
		return nil, fmt.Errorf("update_media: base must be a WIM archive")
	}
	if !imageRootPattern.MatchString(image) {
		return nil, fmt.Errorf("update_media: base requires an explicit /imageN root")
	}
	helper, ok := bootsect.(storage.Reader)
	if !ok || helper.Size() <= 0 {
		return nil, fmt.Errorf("update_media: base requires a nonempty bootsect file")
	}
	for _, name := range []string{"SOFTWARE", "SYSTEM", "COMPONENTS"} {
		if _, err := archive.OpenFile(image + "/Windows/System32/config/" + name); err != nil {
			return nil, fmt.Errorf("update_media: base image %s lacks %s: %w", image, name, err)
		}
	}
	return archive, nil
}
