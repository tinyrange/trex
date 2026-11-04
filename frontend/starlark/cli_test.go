package starlarkfrontend

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIUsageAndREPL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		input    string
		code     int
		out, err string
	}{
		{"help", []string{"trex", "-h"}, "", 0, "", "<script.star> [script arguments...]"},
		{"missing script", []string{"trex"}, "", 1, "", "Usage:"},
		{"repl", []string{"trex", "-repl"}, "x = 20\nx + 22\nprint(x)\n", 0, "42", ""},
		{"repl recovery", []string{"trex", "-repl"}, "1 // 0\n6 * 7\n", 0, "42", "division by zero"},
		{"repl multiline", []string{"trex", "-repl"}, "def twice(x):\n    return x * 2\n\ntwice(21)\n", 0, "42", ""},
		{"repl load", []string{"trex", "-repl"}, "load(\"@stdlib//windows:identity.star\", \"machine_identity\")\nprint(machine_identity(\"TEST\")[\"computer_name\"])\n", 0, "TEST", ""},
		{"empty repl", []string{"trex", "-repl"}, "", 0, ">>>", ""},
		{"repl local load", []string{"trex", "-repl"}, "load(\"//tests:testing.star\", \"equal\")\nequal(42, 42)\n42\n", 0, "42", ""},
		{"repl unterminated line", []string{"trex", "-repl"}, "6 * 7", 0, "42", ""},
		{"unknown flag", []string{"trex", "-not-a-flag"}, "", 1, "", "flag provided but not defined"},
		{"conflicting modes", []string{"trex", "-repl", "-stdlib-docs"}, "", 1, "", "Select one mode"},
		{"repl arguments", []string{"trex", "-repl", "file.star"}, "", 1, "", "does not accept"},
		{"stdin args", []string{"trex", "-", "--flag", "hello"}, "def main(args):\n    print(args)\n", 0, "", "(\"--flag\", \"hello\")"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, err bytes.Buffer
			code := RunCLI(tc.args, strings.NewReader(tc.input), &out, &err)
			if code != tc.code || !strings.Contains(out.String(), tc.out) || !strings.Contains(err.String(), tc.err) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), err.String())
			}
		})
	}
}

// Run the published examples through the actual CLI, including load resolution.
func TestGettingStartedExamples(t *testing.T) {
	for _, name := range []string{"archive_roundtrip", "emulator_call", "emulator_override"} {
		t.Run(name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			script := filepath.Join("scripts", "examples", name+".star")
			if code := RunCLI([]string{"trex", script}, strings.NewReader(""), &out, &stderr); code != 0 {
				t.Fatalf("exit=%d stdout=%s stderr=%s", code, &out, &stderr)
			}
			if out.Len()+stderr.Len() == 0 {
				t.Fatalf("stdout=%s stderr=%s", &out, &stderr)
			}
		})
	}
}

func TestCLIBoundedCPUProfileFinishesBeforeScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.pprof")
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	// The script is blocked on input. Capture must finish independently rather
	// than waiting for script completion (or losing the profile on termination).
	done := make(chan int, 1)
	go func() {
		done <- RunCLI([]string{"trex", "-cpuprofile", path, "-cpuprofile-duration", "10ms", "-"}, reader, io.Discard, io.Discard)
	}()
	deadline := time.Now().Add(5 * time.Second)
	complete := false
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			z, err := gzip.NewReader(bytes.NewReader(data))
			if err == nil {
				_, readErr := io.ReadAll(z)
				z.Close()
				if readErr == nil {
					complete = true
					break
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("script exited before its input was supplied")
	default:
	}
	_, _ = io.WriteString(writer, "def main(args):\n    pass\n")
	writer.Close()
	if code := <-done; code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !complete {
		t.Fatal("CPU profile was not finalized while script was running")
	}
}

func TestCLIBoundedCPUProfileRejectsInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"trex", "-cpuprofile-duration", "-1s", "-"}, {"trex", "-cpuprofile-duration", "1s", "-"}} {
		var diagnostics bytes.Buffer
		if code := RunCLI(args, strings.NewReader(""), io.Discard, &diagnostics); code != 1 || !strings.Contains(diagnostics.String(), "requires -cpuprofile") {
			t.Fatal(code, diagnostics.String())
		}
	}
}
