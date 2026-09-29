//go:build renvo_bundle

package linux

import (
	"bytes"
	"context"
	"renvo.dev/driver"
	"testing"
	"testing/fstest"
)

func TestRenvoStaticLibc(t *testing.T) {
	source := `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
 char *word = malloc(32);
 if (!word) return 10;
 strcpy(word, "Renvo");
 printf("Hello from %s, argc=%d, arg=%s\n", word, argc, argv[1]);
 free(word);
 return 0;
}`
	result, err := driver.CompileCommand(&driver.CommandRequest{Filesystem: sourceFS{fstest.MapFS{"main.c": {Data: []byte(source)}}}, Args: []string{"cc", "main.c"}, Target: "linux/amd64", ArenaSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ok {
		t.Fatalf("compile: %+v", result.Diagnostic)
	}
	var output bytes.Buffer
	run, err := Run(context.Background(), bytes.NewReader(result.Binary), Config{Args: []string{"probe", "world"}, Stdout: &output, Stderr: &output, MaxInstructions: 1000000})
	if err != nil || run.Status != 0 || output.String() != "Hello from Renvo, argc=2, arg=world\n" {
		t.Fatalf("%+v %v output=%q", run, err, output.String())
	}
}
