//go:build renvo_bundle

package toolchain

import "testing"

func TestLibcFcntl(t *testing.T) { runLibcFixture(t, "fcntl", nil, "PASS\n") }
