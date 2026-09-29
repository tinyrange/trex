//go:build renvo_bundle

package buildenv

import "testing"

func TestLibcFcntl(t *testing.T) { runLibcFixture(t, "fcntl", nil, "PASS\n") }
