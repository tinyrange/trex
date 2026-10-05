package repo

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// GitTreeEntry retains original names/modes and external gitlink IDs. It does
// not impose native workspace pathname restrictions on the stored Git graph.
type GitTreeEntry struct {
	Mode uint32
	Name string
	OID  GitOID
}

func ParseGitTree(data []byte, hashBytes int, visit func(GitTreeEntry) error) error {
	return parseGitTree(data, hashBytes, func(mode uint32, name []byte, oid GitOID) error {
		return visit(GitTreeEntry{mode, string(name), oid})
	})
}
func parseGitTree(data []byte, hashBytes int, visit func(uint32, []byte, GitOID) error) error {
	if hashBytes != 20 && hashBytes != 32 {
		return errors.New("invalid Git tree hash size")
	}
	for len(data) > 0 {
		space := bytes.IndexByte(data, ' ')
		if space <= 0 {
			return errors.New("invalid Git tree mode")
		}
		mode, err := strconv.ParseUint(string(data[:space]), 8, 32)
		if err != nil {
			return err
		}
		data = data[space+1:]
		end := bytes.IndexByte(data, 0)
		if end <= 0 || len(data) < end+1+hashBytes {
			return errors.New("truncated Git tree entry")
		}
		name := data[:end]
		oid, _ := GitOIDFromBytes(data[end+1 : end+1+hashBytes])
		data = data[end+1+hashBytes:]
		switch uint32(mode) & 0170000 {
		case 0040000, 0100000, 0120000, 0160000:
		default:
			return fmt.Errorf("unsupported Git tree mode %o", mode)
		}
		if err := visit(uint32(mode), name, oid); err != nil {
			return err
		}
	}
	return nil
}

// GitLinks parses semantic object references without reserializing metadata.
// Signatures, encodings, unknown headers, and all original body bytes survive.
// Gitlinks point outside this repository and are deliberately not closure edges.
func GitLinks(kind byte, data []byte, hashBytes int, visit func(GitOID, byte) error) error {
	if kind == GitBlob {
		return nil
	}
	if kind == GitTree {
		return parseGitTree(data, hashBytes, func(mode uint32, _ []byte, oid GitOID) error {
			switch mode & 0170000 {
			case 0160000:
				return nil
			case 0040000:
				return visit(oid, GitTree)
			default:
				return visit(oid, GitBlob)
			}
		})
	}
	if kind != GitCommit && kind != GitTag {
		return errors.New("invalid Git object type")
	}
	end := bytes.Index(data, []byte("\n\n"))
	if end < 0 {
		return errors.New("Git metadata has no header/body separator")
	}
	treeCount, objectCount, typeCount := 0, 0, 0
	var target GitOID
	var targetKind byte
	for _, line := range bytes.Split(data[:end], []byte{'\n'}) {
		field, value, ok := bytes.Cut(line, []byte{' '})
		if !ok {
			continue
		}
		switch {
		case kind == GitCommit && (string(field) == "tree" || string(field) == "parent"):
			id, err := ParseGitOID(string(value))
			if err != nil || int(id[32]) != hashBytes {
				return errors.New("invalid commit reference")
			}
			want := GitCommit
			if string(field) == "tree" {
				want = GitTree
				treeCount++
			}
			if err := visit(id, want); err != nil {
				return err
			}
		case kind == GitTag && string(field) == "object":
			var err error
			target, err = ParseGitOID(string(value))
			if err != nil || int(target[32]) != hashBytes {
				return errors.New("invalid tag target")
			}
			objectCount++
		case kind == GitTag && string(field) == "type":
			targetKind = GitType(string(value))
			typeCount++
		}
	}
	if kind == GitCommit {
		if treeCount != 1 {
			return errors.New("commit must reference exactly one tree")
		}
		return nil
	}
	if objectCount != 1 || typeCount != 1 || targetKind == 0 {
		return errors.New("invalid annotated tag header")
	}
	return visit(target, targetKind)
}
