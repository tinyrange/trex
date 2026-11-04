package native

import (
	"strings"
	"testing"

	"github.com/tinyrange/trex/archive/wim"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestExternalBaseRequiresExplicitImageAndBootHelper(t *testing.T) {
	helper := &starfile.Bytes{Name: "bootsect.exe", Data: []byte("helper")}
	for _, tc := range []struct {
		base   starlark.Value
		image  string
		helper starlark.Value
		want   string
	}{
		{starlark.None, "/image6", helper, "require base"},
		{starlark.None, "", helper, "require base"},
		{starlark.String("not a WIM"), "/image6", helper, "WIM archive"},
		{&wim.Archive{}, "", helper, "explicit /imageN"},
		{&wim.Archive{}, "/image0", helper, "explicit /imageN"},
		{&wim.Archive{}, "/image6/../image1", helper, "explicit /imageN"},
		{&wim.Archive{}, "/image6", starlark.None, "nonempty bootsect"},
		{&wim.Archive{}, "/image6", &starfile.Bytes{}, "nonempty bootsect"},
	} {
		if _, err := externalServicingBase(tc.base, tc.image, tc.helper); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("image %q: %v", tc.image, err)
		}
	}
	if base, err := externalServicingBase(starlark.None, "", starlark.None); err != nil || base != nil {
		t.Fatalf("ordinary media: %v", err)
	}
}
