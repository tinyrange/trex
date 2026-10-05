package gitstore

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeltaHistory(t *testing.T) {
	_, dir, _ := fixture(t)
	parent := command(t, dir, nil, "rev-parse", "HEAD")
	for i := 0; i < 30; i++ {
		body := []byte(strings.Repeat("a line of shared content\n", 3000) + fmt.Sprint(i) + "\n")
		blob := command(t, dir, body, "hash-object", "-w", "--stdin")
		tree := command(t, dir, []byte("100644 blob "+blob+"\tfile\n"), "mktree")
		commit := []byte(fmt.Sprintf("tree %s\nparent %s\nauthor Test <t@e> 1000000000 +0000\ncommitter Test <t@e> 1000000000 +0000\n\n%d\n", tree, parent, i))
		parent = command(t, dir, commit, "hash-object", "-w", "-t", "commit", "--stdin")
	}
	command(t, dir, nil, "update-ref", "refs/heads/main", parent)
	for _, ofs := range []bool{false, true} {
		t.Run(fmt.Sprint(ofs), func(t *testing.T) {
			args := []string{"-C", dir, "pack-objects", "--stdout", "--all", "--window=50", "--depth=50"}
			if ofs {
				args = append(args, "--delta-base-offset")
			}
			cmd := exec.Command("git", args...)
			pack, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			if len(pack) > 30000 {
				t.Fatal("fixture unexpectedly lacks effective deltas", len(pack))
			}
			d := Download{Head: parent, Refs: map[string]string{"refs/heads/main": parent}, Objects: binary.BigEndian.Uint32(pack[8:12]), PackBytes: int64(len(pack)), PackHash: hex.EncodeToString(pack[len(pack)-20:])}
			r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "delta.scs"))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			report, err := ImportPack(context.Background(), r, bytes.NewReader(pack), d, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if report.Objects != 98 {
				t.Fatal(report.Objects)
			}
			for _, id := range r.GitObjectIDs() {
				kind, body, err := r.ReadGitObject(id)
				if err != nil {
					t.Fatal(err)
				}
				want, err := exec.Command("git", "-C", dir, "cat-file", repo.GitTypeName(kind), id.String()).Output()
				if err != nil || !bytes.Equal(body, want) {
					t.Fatal("delta reconstruction", id, err)
				}
			}
			w, err := r.CheckoutGit(context.Background(), "git", "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			b, err := w.ReadFile("file")
			if err != nil || !bytes.HasSuffix(b, []byte("29\n")) {
				t.Fatal(err)
			}
			// A corrupted spool must never publish refs, even when native objects exist.
			pack[len(pack)/2] ^= 1
			if _, err = ImportPack(context.Background(), r, bytes.NewReader(pack), d, Options{Name: "bad"}); err == nil {
				t.Fatal("corruption accepted")
			}
			if _, err = r.GitCatalog("bad"); err == nil {
				t.Fatal("corruption published")
			}
		})
	}
}
func TestMissingGraphDoesNotPublish(t *testing.T) {
	_, dir, _ := fixture(t)
	body := []byte("tree " + strings.Repeat("2", 40) + "\nauthor T <t@e> 1 +0000\ncommitter T <t@e> 1 +0000\n\nmissing tree\n")
	id := command(t, dir, body, "hash-object", "-w", "-t", "commit", "--stdin")
	cmd := exec.Command("git", "-C", dir, "pack-objects", "--stdout")
	cmd.Stdin = strings.NewReader(id + "\n")
	pack, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha1.Sum(pack[:len(pack)-20])
	d := Download{Head: id, Refs: map[string]string{"refs/heads/main": id}, Objects: 1, PackBytes: int64(len(pack)), PackHash: hex.EncodeToString(hash[:])}
	r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "missing.scs"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = ImportPack(context.Background(), r, bytes.NewReader(pack), d, Options{})
	if err == nil || !strings.Contains(err.Error(), "incomplete Git graph") {
		t.Fatal(err)
	}
	if _, err = r.GitCatalog("git"); err == nil {
		t.Fatal("incomplete graph published")
	}
}
