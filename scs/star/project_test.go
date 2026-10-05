package script_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/tinyrange/trex/renvostar"
	scsnative "github.com/tinyrange/trex/scs/native"
	scsstar "github.com/tinyrange/trex/scs/star"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Host Git builds and serves only a tiny oracle fixture. All clone decoding,
// workspace edits, compilation and repository reopen happen inside trex.
func TestCloneProjectBuildPublishReopen(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "project.git")
	command(t, root, nil, "init", "--bare", dir)
	git, e := exec.LookPath("git")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(&cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}})
	defer server.Close()
	url := server.URL + "/project.git"
	main := command(t, dir, []byte("int main(void) { return 1; }\n"), "hash-object", "-w", "--stdin")
	var tree bytes.Buffer
	fmt.Fprintf(&tree, "100644 main.c%c", 0)
	raw, _ := hex.DecodeString(main)
	tree.Write(raw)
	treeID := command(t, dir, tree.Bytes(), "hash-object", "-w", "-t", "tree", "--stdin")
	commit := command(t, dir, []byte(fmt.Sprintf("tree %s\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\nproject\n", treeID)), "hash-object", "-w", "-t", "commit", "--stdin")
	command(t, dir, nil, "update-ref", "refs/heads/main", commit)
	command(t, dir, nil, "symbolic-ref", "HEAD", "refs/heads/main")
	globals, e := starlark.ExecFile(&starlark.Thread{}, "project.star", `
r = scs.memory(max_bytes = 4 * 1024 * 1024)
report = r.clone(url, max_pack_bytes = 1024 * 1024, max_native_bytes = 4 * 1024 * 1024)
source = r.checkout_git()
old = source.open_file("main.c")
source.publish("original")
project = source.fork()
project.write_file("main.c", old.splice(24, 1, "0"))
build = renvo.cc(source = project, input = "main.c", target = "windows/386", arena_size = 1024 * 1024)
project.write_file("app.exe", build.binary)
project.publish("built")
artifact = r.file()
r.close()
reopened = scs.memory(artifact, max_bytes = 4 * 1024 * 1024)
result = reopened.checkout("built")
header = result.open_file("app.exe").bytes(0, 2)
original = reopened.checkout("original").read_file("main.c")
modified = result.read_file("main.c")
reopened.close()
`, starlark.StringDict{
		"scs":   starlarkstruct.FromStringDict(starlark.String("scs"), scsstar.Builtins(nil, nil, scsnative.GitTransport)),
		"renvo": starlarkstruct.FromStringDict(starlark.String("renvo"), renvostar.Builtins()),
		"url":   starlark.String(url),
	})
	if e != nil {
		t.Fatal(e)
	}
	if globals["header"] != starlark.Bytes("MZ") {
		t.Fatal("build did not produce PE", globals["header"])
	}
	if globals["original"] != starlark.String("int main(void) { return 1; }\n") || globals["modified"] != starlark.String("int main(void) { return 0; }\n") {
		t.Fatal("fork isolation failed", globals)
	}
}

// A bounded Git executable oracle, never part of the production ingestion path.
func command(t *testing.T, dir string, input []byte, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5_000_000_000)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("git %v: %v: %s", args, e, out)
	}
	return strings.TrimSpace(string(out))
}
