package gpt

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("gpt", 60, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !(len(prefix) >= 520 && string(prefix[512:520]) == "EFI PART") && !(len(prefix) >= 4104 && string(prefix[4096:4104]) == "EFI PART") {
			return nil, auto.ErrNoMatch
		}
		return adapter.Parse(GPTBuiltin, source, options)
	})
}
