package repo

import (
	"encoding/binary"
	"errors"
)

// Typed native bodies embed the compatibility identity; no separate descriptor
// is necessary unless an already-existing body needs an additional Git identity.
func bodyIdentity(data []byte) (GitOID, byte, int, error) {
	if len(data) < 74 {
		return GitOID{}, 0, 0, errors.New("short body")
	}
	if data[0] == 1 {
		return GitOID{}, 0, 42, nil
	}
	if data[0] != 2 || len(data) < 76 {
		return GitOID{}, 0, 0, errors.New("invalid body identity")
	}
	kind, n := data[42], int(data[43])
	if kind < GitCommit || kind > GitTag || (n != 20 && n != 32) || len(data) < 44+n+32 {
		return GitOID{}, 0, 0, errors.New("invalid body identity")
	}
	id, _ := GitOIDFromBytes(data[44 : 44+n])
	return id, kind, 44 + n, nil
}
func (r *Repository) registerBodyGit(id ID, data []byte) error {
	oid, kind, _, err := bodyIdentity(data)
	if err != nil {
		return err
	}
	if !oid.Valid() {
		return nil
	}
	return r.registerGitLocation(oid, gitLocation{ID: key(id), Body: key(id), Kind: kind, Size: int64(binary.BigEndian.Uint64(data[2:10]))})
}
func (r *Repository) registerGitLocation(oid GitOID, v gitLocation) error {
	if old, ok := r.lookupGit(oid); ok {
		if old != v {
			return errors.New("Git ID collision")
		}
		return nil
	}
	if r.gitObjects == nil {
		r.gitObjects = map[GitOID]gitLocation{}
	}
	r.gitObjects[oid] = v
	if r.fast != nil {
		r.fast.dirtyGit[oid] = v.ID
	}
	r.gitStats.Objects++
	r.gitStats.Bytes += uint64(v.Size)
	if r.gitStats.Types == nil {
		r.gitStats.Types = map[string]GitTypeStats{}
	}
	s := r.gitStats.Types[GitTypeName(v.Kind)]
	s.Objects++
	s.Bytes += uint64(v.Size)
	r.gitStats.Types[GitTypeName(v.Kind)] = s
	return nil
}
