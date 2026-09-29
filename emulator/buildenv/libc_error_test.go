//go:build renvo_bundle

package buildenv

import (
	"bytes"
	"context"
	"github.com/tinyrange/trex/emulator/linux"
	"github.com/tinyrange/trex/emulator/shell"
	"renvo.dev/driver"
	"testing"
)

type fullOutput struct{}

func (fullOutput) Write([]byte) (int, error) { return 0, linux.Errno(28) }
func TestLibcOutputFailureAtExit(t *testing.T) {
	source := `#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
static void close_output(void) {
 int failed = ferror(stdout);
 if (__fpending(stdout) != 0) _exit(11);
 if (fclose(stdout) != 0) _exit(12);
 if (failed) _exit(23);
}
int main(void) {
 if (atexit(close_output) != 0) return 10;
 if (printf("lost output") != EOF || !ferror(stdout) || errno != ENOSPC) return 13;
 return 0;
}`
	files, _ := shell.NewMemoryFS(16 << 20)
	if err := files.WriteFile("/main.c", []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	compiled, err := driver.CompileCommand(&driver.CommandRequest{Filesystem: &sourceFS{fs: files, dir: "/"}, Args: []string{"cc", "main.c"}, Target: "linux/amd64", ArenaSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Ok {
		t.Fatalf("compile: %+v", compiled.Diagnostic)
	}
	result, err := linux.Run(context.Background(), bytes.NewReader(compiled.Binary), linux.Config{Stdout: fullOutput{}})
	if err != nil || result.Status != 23 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
