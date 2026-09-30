package channel

import "errors"

// ErrNoSpace reports a storage write failure without host-specific errno values.
var ErrNoSpace = errors.New("no space left on device")
