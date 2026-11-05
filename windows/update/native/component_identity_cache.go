package native

import "github.com/tinyrange/trex/windows/uup"

type stageContentIdentity struct {
	size int64
	hash [32]byte
}

func declaredStageContent(effect uup.StageFileEffect, sizes map[string]int64, hashes map[string][32]byte, normalize func(string) string) (int64, [32]byte, bool) {
	if effect.SourceMode == "predecessor" && effect.SourceDescriptor != nil {
		return effect.SourceDescriptor.Length, effect.SourceDescriptor.SHA256, true
	}
	if effect.SourceMode == "payload" {
		name := normalize(effect.SourceName)
		size, sizeKnown := sizes[name]
		hash, hashKnown := hashes[name]
		return size, hash, sizeKnown && hashKnown
	}
	return 0, [32]byte{}, false
}
