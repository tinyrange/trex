package gitstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
)

func command(t *testing.T, dir string, input []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}
func fixture(t *testing.T) (string, string, map[string]string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "fixture.git")
	command(t, root, nil, "init", "--bare", dir)
	ids := map[string]string{}
	put := func(name, kind string, data []byte) string {
		id := command(t, dir, data, "hash-object", "-w", "-t", kind, "--stdin")
		ids[name] = id
		return id
	}
	blob := put("blob", "blob", []byte{0, 255, 1, 2, '\n'})
	link := put("link", "blob", []byte("binary"))
	var tree bytes.Buffer
	entry := func(mode, name, id string) {
		fmt.Fprintf(&tree, "%s %s%c", mode, name, 0)
		raw, _ := hex.DecodeString(id)
		tree.Write(raw)
	}
	entry("100755", "binary", blob)
	entry("120000", "link", link)
	// A gitlink refers to another repository and need not exist in this pack.
	entry("160000", "module", "1111111111111111111111111111111111111111")
	treeID := put("tree", "tree", tree.Bytes())
	commit := put("commit", "commit", []byte(fmt.Sprintf("tree %s\nauthor Test <test@example.com> 1000000000 +0000\ncommitter Test <test@example.com> 1000000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n test fixture, not a valid signature\n -----END PGP SIGNATURE-----\n\nmessage\n", treeID)))
	tag := put("tag", "tag", []byte(fmt.Sprintf("object %s\ntype commit\ntag signed\ntagger Test <test@example.com> 1000000000 +0000\n\nannotation\n-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n", commit)))
	put("tag-blob", "tag", []byte(fmt.Sprintf("object %s\ntype blob\ntag blob-tag\ntagger Test <test@example.com> 1000000000 +0000\n\nblob tag\n", blob)))
	put("tag-tree", "tag", []byte(fmt.Sprintf("object %s\ntype tree\ntag tree-tag\ntagger Test <test@example.com> 1000000000 +0000\n\ntree tag\n", treeID)))
	put("tag-tag", "tag", []byte(fmt.Sprintf("object %s\ntype tag\ntag nested\ntagger Test <test@example.com> 1000000000 +0000\n\nnested tag\n", tag)))
	command(t, dir, nil, "update-ref", "refs/heads/main", commit)
	for _, name := range []string{"tag", "tag-blob", "tag-tree", "tag-tag"} {
		command(t, dir, nil, "update-ref", "refs/tags/"+name, ids[name])
	}
	command(t, dir, nil, "update-ref", "refs/tags/lightweight", commit)
	command(t, dir, nil, "symbolic-ref", "HEAD", "refs/heads/main")
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(&cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}})
	t.Cleanup(server.Close)
	return server.URL + "/fixture.git", dir, ids
}
func TestNativeClone(t *testing.T) { testNativeClone(t, scsnative.CreateOptimized) }
func TestLegacyClone(t *testing.T) { testNativeClone(t, scsnative.Create) }
func testNativeClone(t *testing.T, create func(string) (*repo.Repository, error)) {
	url, dir, ids := fixture(t)
	filename := filepath.Join(t.TempDir(), "clone.scs")
	r, err := create(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	report, err := cloneFixture(context.Background(), r, url, Options{Name: "git"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Objects != uint64(len(ids)) {
		t.Fatalf("objects %d != %d", report.Objects, len(ids))
	}
	for _, typ := range []string{"blob", "tree", "commit", "tag"} {
		if report.Types[typ].Objects == 0 {
			t.Fatalf("missing type %s", typ)
		}
	}
	if _, err := r.GitCatalog("git"); err != nil {
		t.Fatal("no completed native Git catalog", err)
	}

	check := func(r *repo.Repository) {
		t.Helper()
		for name, text := range ids {
			id, _ := repo.ParseGitOID(text)
			kind, got, e := r.ReadGitObject(id)
			if e != nil {
				t.Fatal(name, e)
			}
			cmd := exec.Command("git", "-C", dir, "cat-file", repo.GitTypeName(kind), text)
			want, e := cmd.Output()
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s body changed", name)
			}
			if e = r.VerifyGitObject(id); e != nil {
				t.Fatal(name, e)
			}
		}
		for _, name := range []string{"tag", "tag-blob", "tag-tree", "tag-tag"} {
			id, _ := repo.ParseGitOID(ids[name])
			_, kind, e := r.PeelGit(id)
			if e != nil || kind == repo.GitTag {
				t.Fatal("peel", name, kind, e)
			}
		}
	}
	check(r)
	w, err := r.CheckoutGit(context.Background(), "git", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	stat, err := w.Stat("module")
	if err != nil || stat.Kind != "gitlink" || stat.GitOID != strings.Repeat("1", 40) {
		t.Fatal(stat, err)
	}
	if _, err = w.ReadFile("module"); err == nil {
		t.Fatal("gitlink treated as file")
	}
	if err = w.Chmod("module", 0755); err == nil {
		t.Fatal("gitlink mode changed")
	}
	stat, err = w.Stat("binary")
	if err != nil || stat.Mode != 0755 {
		t.Fatal(stat, err)
	}
	blob, _ := repo.ParseGitOID(ids["blob"])
	obj, err := r.GitObject(blob)
	if err != nil || (fmt.Sprint(stat.Blocks) != fmt.Sprint(obj.Blocks) || stat.Body != obj.Body) {
		t.Fatal("checkout did not share blocks", err)
	}
	snap, err := w.Publish("main")
	if err != nil {
		t.Fatal(err)
	}
	fork, err := r.Fork(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err = fork.WriteFile("binary", []byte("edited")); err != nil {
		t.Fatal(err)
	}
	original, err := w.ReadFile("binary")
	if err != nil || bytes.Equal(original, []byte("edited")) {
		t.Fatal("fork isolation", err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = scsnative.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	check(r)
	w, err = r.Checkout("main")
	if err != nil {
		t.Fatal(err)
	}
	stat, err = w.Stat("module")
	if err != nil || stat.Kind != "gitlink" {
		t.Fatal("reopened gitlink", stat, err)
	}
	t.Logf("report %+v", report)
}
