//go:build renvo_bundle

package buildenv

import (
	"bytes"
	"context"
	"github.com/tinyrange/trex/emulator/shell"
	"os"
	"strings"
	"testing"
)

func TestLibcFileStreams(t *testing.T) {
	runLibcFixture(t, "streams", nil, "PASS\n")
}
func TestLibcWideAndExit(t *testing.T) {
	for _, arg := range []string{"", "exit", "immediate"} {
		t.Run(arg, func(t *testing.T) {
			want := "wide: Aé😀\n"
			if arg != "immediate" {
				want += "second\nfirst\n"
			}
			runLibcFixture(t, "wide_exit", []string{arg}, want)
		})
	}
}
func runLibcFixture(t *testing.T, fixture string, args []string, want string) {
	t.Helper()
	source, err := os.ReadFile("../../renvo/libc/tests/" + fixture + ".c")
	if err != nil {
		t.Fatal(err)
	}
	files, err := shell.NewMemoryFS(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	env, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Mkdir("/work"); err != nil {
		t.Fatal(err)
	}
	if err := files.WriteFile("/work/main.c", source, 0644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := shell.Run(context.Background(), strings.NewReader("cc main.c -o streams && ./streams "+strings.Join(args, " ")), "test", shell.Config{
		FS: files, Dir: "/work", Env: map[string]string{"PATH": "/bin", "RENVO_LIBC_TEST": "guest", "LC_ALL": "C.UTF-8"}, Command: env.Command, Stdout: &output, Stderr: &output,
	})
	if err != nil || result.Status != 0 || output.String() != want {
		t.Fatalf("result=%+v err=%v output=%s", result, err, output.String())
	}
	if fixture != "streams" {
		return
	}
	data, err := files.ReadFile("/work/data")
	if err != nil || len(data) != 0 {
		t.Fatalf("final truncated file=%q err=%v", data, err)
	}
}
