package uup

import (
	"iter"
	"maps"
)

// cbsSnapshotTable is a two-level copy-on-write table. An update copies only
// two small pointer arrays and the changed leaf maps, rather than a bucket
// containing hundreds of unrelated packages or every published update.
// Values and shared nodes are immutable. Evaluation memo is never shared.
type cbsSnapshotTable[V any] struct {
	groups [64]*cbsSnapshotGroup[V]
	count  int
}
type cbsSnapshotGroup[V any] [64]map[string]V

func cbsContextBucket(key string) uint16 {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h = (h ^ uint32(key[i])) * 16777619
	}
	return uint16(h^(h>>16)) & 4095
}

func (p *cbsSnapshotTable[V]) lookup(key string) (V, bool) {
	b := cbsContextBucket(key)
	if group := p.groups[b>>6]; group != nil {
		value, ok := group[b&63][key]
		return value, ok
	}
	var zero V
	return zero, false
}

// add is only for initial construction, before any snapshot shares the table.
func (p *cbsSnapshotTable[V]) add(key string, value V) {
	b := cbsContextBucket(key)
	g, l := b>>6, b&63
	if p.groups[g] == nil {
		p.groups[g] = new(cbsSnapshotGroup[V])
	}
	if p.groups[g][l] == nil {
		p.groups[g][l] = make(map[string]V)
	}
	if _, ok := p.groups[g][l][key]; !ok {
		p.count++
	}
	p.groups[g][l][key] = value
}

func (p *cbsSnapshotTable[V]) all() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		for _, group := range p.groups {
			if group == nil {
				continue
			}
			for _, bucket := range group {
				for key, value := range bucket {
					if !yield(key, value) {
						return
					}
				}
			}
		}
	}
}

func (p *cbsSnapshotTable[V]) changed(changes map[string]V, deletes []string) cbsSnapshotTable[V] {
	next := *p
	var copiedGroups [64]bool
	var copiedLeaves [64]uint64
	writable := func(key string) map[string]V {
		b := cbsContextBucket(key)
		g, l := b>>6, b&63
		if !copiedGroups[g] {
			group := new(cbsSnapshotGroup[V])
			if p.groups[g] != nil {
				*group = *p.groups[g]
			}
			next.groups[g] = group
			copiedGroups[g] = true
		}
		if copiedLeaves[g]&(uint64(1)<<l) == 0 {
			leaf := maps.Clone(next.groups[g][l])
			if leaf == nil {
				leaf = make(map[string]V)
			}
			next.groups[g][l] = leaf
			copiedLeaves[g] |= uint64(1) << l
		}
		return next.groups[g][l]
	}
	for key, value := range changes {
		leaf := writable(key)
		if _, ok := leaf[key]; !ok {
			next.count++
		}
		leaf[key] = value
	}
	for _, key := range deletes {
		// Avoid allocating a leaf merely to delete a nonexistent override.
		if _, ok := next.lookup(key); !ok {
			continue
		}
		delete(writable(key), key)
		next.count--
	}
	return next
}

// Package identities are interned once. Snapshots copy only touched pointer
// pages; they never rehash a long identity to choose a bucket or clone maps of
// unrelated packages. The immutable dictionaries are shared by all snapshots.
type cbsPackageContexts struct {
	byKey      map[string]uint32
	byIdentity map[cbsIdentityFields]uint32
	keys       []string
	groups     [64]*cbsPackageGroup
	count      int
}
type cbsPackageGroup [64]*cbsPackageLeaf
type cbsPackageLeaf [16]*cbsUpdateContext
type cbsIdentityFields struct{ name, token, architecture, language, version string }

func cbsIdentityParts(id AssemblyIdentity) cbsIdentityFields {
	language := id.Language
	if language == "" {
		language = "neutral"
	}
	return cbsIdentityFields{id.Name, id.PublicKeyToken, id.ProcessorArchitecture, language, id.Version}
}
func (p *cbsPackageContexts) keyForIdentity(id AssemblyIdentity) string {
	if slot, ok := p.byIdentity[cbsIdentityParts(id)]; ok {
		return p.keys[slot]
	}
	return id.ExactKey()
}
func (p *cbsPackageContexts) at(slot uint32) *cbsUpdateContext {
	return p.groups[slot>>10][(slot>>4)&63][slot&15]
}
func (p *cbsPackageContexts) get(key string) *cbsUpdateContext {
	slot, ok := p.byKey[key]
	if !ok {
		return nil
	}
	return p.at(slot)
}

// add is only used during validated initial construction.
func (p *cbsPackageContexts) add(key string, value *cbsUpdateContext) {
	if p.byKey == nil {
		p.byKey = make(map[string]uint32)
		p.byIdentity = make(map[cbsIdentityFields]uint32)
	}
	slot, ok := p.byKey[key]
	if !ok {
		slot = uint32(p.count)
		p.byKey[key] = slot
		p.keys = append(p.keys, key)
		p.count++
	}
	p.byIdentity[cbsIdentityParts(value.input.Manifest.Identity)] = slot
	g, l := slot>>10, (slot>>4)&63
	if p.groups[g] == nil {
		p.groups[g] = new(cbsPackageGroup)
	}
	if p.groups[g][l] == nil {
		p.groups[g][l] = new(cbsPackageLeaf)
	}
	p.groups[g][l][slot&15] = value
}
func (p *cbsPackageContexts) all() iter.Seq2[string, *cbsUpdateContext] {
	return func(yield func(string, *cbsUpdateContext) bool) {
		for slot, key := range p.keys {
			if !yield(key, p.at(uint32(slot))) {
				return
			}
		}
	}
}
func (p *cbsPackageContexts) with(changes map[string]*cbsUpdateContext) cbsPackageContexts {
	next := *p
	var copiedGroups [64]bool
	var copiedLeaves [64]uint64
	for key, value := range changes {
		slot, ok := p.byKey[key]
		if !ok {
			panic("unvalidated CBS context replacement")
		}
		g, l := slot>>10, (slot>>4)&63
		if !copiedGroups[g] {
			group := *p.groups[g]
			next.groups[g] = &group
			copiedGroups[g] = true
		}
		if copiedLeaves[g]&(uint64(1)<<l) == 0 {
			leaf := *p.groups[g][l]
			next.groups[g][l] = &leaf
			copiedLeaves[g] |= uint64(1) << l
		}
		next.groups[g][l][slot&15] = value
	}
	return next
}
