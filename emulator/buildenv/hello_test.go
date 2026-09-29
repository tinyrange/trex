package buildenv

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/tinyrange/trex/emulator/shell"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in integration workload: download a fixed GNU release into memory only.
// No tarball, extracted tree, config log or compiler intermediate is written to
// the host. This is not part of the offline unit suite.
func TestHelloConfigure(t *testing.T) {
	mode := os.Getenv("TREX_HELLO_CONFIGURE")
	if mode == "" {
		t.Skip("set TREX_HELLO_CONFIGURE=help, configure or build for the network integration workload")
	}
	if mode != "help" && mode != "configure" && mode != "build" {
		t.Fatal("invalid TREX_HELLO_CONFIGURE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	m := loadHello(t, ctx)
	source, err := m.ReadFile("/hello-2.12.1/configure")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{}
	if mode == "help" {
		args = []string{"--help"}
	}
	var output, diagnostic bytes.Buffer
	environment, err := New(m)
	if err != nil {
		t.Fatal(err)
	}
	// Select a full-moon test date so upstream greeting-2 cannot skip.
	environment.Now = func() time.Time { return time.Date(2000, 1, 21, 0, 0, 0, 0, time.UTC) }
	result, err := shell.Run(ctx, bytes.NewReader(source), "./configure", shell.Config{Command: environment.Command, FS: m, Dir: "/hello-2.12.1", Env: map[string]string{"PATH": "/bin:/usr/bin", "SHELL": "/bin/sh", "LC_ALL": "C"}, Args: args, Stdout: &output, Stderr: &diagnostic, MaxSteps: 1000000})
	if err != nil || result.Status != 0 {
		if log, readErr := m.ReadFile("/hello-2.12.1/config.log"); readErr == nil {
			t.Logf("config.log tail:\n%s", tail(string(log), 4500))
			if end := strings.LastIndex(string(log), "## Cache variables. ##"); end >= 0 {
				t.Logf("last configure probes:\n%s", tail(string(log[:end]), 6500))
			}
			seen := make(map[string]bool)
			for _, line := range strings.Split(string(log), "\n") {
				if strings.Contains(line, "RENVO-") && !seen[line] && len(seen) < 16 {
					t.Logf("compiler diagnostic: %s", line)
					seen[line] = true
				}
			}
		}
		if err != nil {
			if generated, e := m.ReadFile("/hello-2.12.1/config.status"); e == nil {
				matches := regexp.MustCompile(`config.status:([0-9]+):`).FindAllStringSubmatch(err.Error(), -1)
				if len(matches) > 0 {
					line, _ := strconv.Atoi(matches[len(matches)-1][1])
					lines := strings.Split(string(generated), "\n")
					for n := max(1, line-3); n <= min(len(lines), line+3); n++ {
						t.Logf("config.status:%d: %s", n, lines[n-1])
					}
				}
			}
			matches := regexp.MustCompile(`\./configure:([0-9]+):`).FindAllStringSubmatch(err.Error(), -1)
			if len(matches) > 0 {
				line, _ := strconv.Atoi(matches[len(matches)-1][1])
				lines := strings.Split(string(source), "\n")
				for n := max(1, line-3); n <= min(len(lines), line+3); n++ {
					t.Logf("%d: %s", n, lines[n-1])
				}
			}
		}
		// A small source window identifies the decisive operation without dumping a
		// generated configure script or leaving intermediate files on the host.
		t.Fatalf("configure status=%d steps=%d error=%v\nstdout tail:\n%s\nstderr tail:\n%s", result.Status, result.Steps, err, tail(output.String(), 2500), tail(diagnostic.String(), 2500))
	}
	if mode == "help" && !strings.Contains(output.String(), "GNU Hello") {
		t.Fatalf("missing Hello help: %s", tail(output.String(), 1000))
	}
	if mode != "help" {
		for _, name := range []string{"config.status", "config.h", "Makefile"} {
			if _, err := m.Stat("/hello-2.12.1/" + name); err != nil {
				t.Fatal(err)
			}
		}
	}
	if mode == "build" {
		output.Reset()
		diagnostic.Reset()
		result, err = shell.Run(ctx, strings.NewReader("make && make check && ./hello"), "hello-build", shell.Config{Command: environment.Command, FS: m, Dir: "/hello-2.12.1", Env: map[string]string{"PATH": "/bin:/usr/bin", "SHELL": "/bin/sh", "LC_ALL": "C"}, Stdout: &output, Stderr: &diagnostic, MaxSteps: 2000000})
		if err != nil || result.Status != 0 {
			t.Fatalf("build status=%d steps=%d error=%v\nstdout tail:\n%s\nstderr tail:\n%s", result.Status, result.Steps, err, tail(output.String(), 4500), tail(diagnostic.String(), 4500))
		}
		for _, test := range []string{"atexit-1", "greeting-1", "greeting-2", "hello-1", "last-1", "operand-1", "traditional-1"} {
			if !strings.Contains(output.String(), "PASS: tests/"+test) {
				t.Fatalf("upstream test did not pass: %s\n%s", test, tail(output.String(), 4000))
			}
		}
		t.Logf("upstream test summary:\n%s", tail(output.String(), 1200))
		verifyHelloELF(t, ctx, m, environment)
		if !strings.HasSuffix(output.String(), "Hello, world!\n") {
			t.Fatalf("missing Hello output: %s", tail(output.String(), 1500))
		}
	}
	t.Log(fmt.Sprintf("configure completed: %d shell steps, %d output bytes", result.Steps, output.Len()))
}
func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func loadHello(t *testing.T, ctx context.Context) *shell.MemoryFS {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}
	archive, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive) > 8<<20 {
		t.Fatal("archive size limit")
	}
	const expectedSHA256 = "8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20"
	if fmt.Sprintf("%x", sha256.Sum256(archive)) != expectedSHA256 {
		t.Fatal("archive checksum mismatch")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	m, err := shell.NewMemoryFS(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(compressed)
	count := 0
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
		if count > 10000 {
			t.Fatal("entry limit")
		}
		if path.IsAbs(h.Name) || strings.Contains(h.Name, "../") {
			t.Fatalf("unsafe archive path %q", h.Name)
		}
		name := path.Clean("/" + h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := m.Mkdir(name); err != nil {
				t.Fatal(err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > 8<<20 {
				t.Fatalf("file size limit: %s", name)
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.WriteFile(name, data, fs.FileMode(h.Mode)); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unsupported archive entry %s type %d", name, h.Typeflag)
		}
		if err := m.SetModTime(name, h.ModTime); err != nil {
			t.Fatal(err)
		}
	}

	return m
}

// Only the final executable is written to the host, never source or build
// intermediates. Both execution paths consume the identical image bytes.
func verifyHelloELF(t *testing.T, ctx context.Context, m *shell.MemoryFS, environment *Environment) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Log("native ELF comparison requires linux/amd64")
		return
	}
	image, err := m.ReadFile("/hello-2.12.1/hello")
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "hello")
	if err = os.WriteFile(filename, image, 0700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		args   []string
		status int
		want   string
		full   bool
	}{
		{name: "default", want: "Hello, world!\n"},
		{name: "greeting", args: []string{"--greeting=From memory"}, want: "From memory\n"},
		{name: "long-greeting", args: []string{"-g", strings.Repeat("xyz", 1000)}, want: strings.Repeat("xyz", 1000) + "\n"},
		{name: "traditional", args: []string{"--traditional"}, want: "hello, world\n"},
		{name: "help", args: []string{"--help"}, want: "Usage:"},
		{name: "version", args: []string{"--version"}, want: "hello (GNU Hello) 2.12.1"},
		{name: "invalid-option", args: []string{"--not-an-option"}, status: 1},
		{name: "extra-operand", args: []string{"operand"}, status: 1},
		{name: "full-device", status: 1, full: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var vo, ve, no, ne bytes.Buffer
			in := shell.Invocation{Args: append([]string{"./hello"}, tc.args...), Env: map[string]string{"LC_ALL": "C"}, Dir: "/hello-2.12.1", Stdout: &vo, Stderr: &ve, Stdin: strings.NewReader("")}
			command := exec.CommandContext(ctx, filename, tc.args...)
			command.Args[0] = "./hello"
			command.Env = []string{"LC_ALL=C"}
			command.Stdout = &no
			command.Stderr = &ne
			if tc.full {
				vf, err := m.Open("/dev/full", shell.Write)
				if err != nil {
					t.Fatal(err)
				}
				defer vf.Close()
				in.Stdout = vf
				nf, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer nf.Close()
				command.Stdout = nf
			}
			status, err := environment.Command(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			nativeErr := command.Run()
			nativeStatus := 0
			if nativeErr != nil {
				if exit, ok := nativeErr.(*exec.ExitError); ok {
					nativeStatus = exit.ExitCode()
				} else {
					t.Fatal(nativeErr)
				}
			}
			if status != tc.status || nativeStatus != tc.status || vo.String() != no.String() || ve.String() != ne.String() {
				t.Fatalf("virtual=%d %q %q native=%d %q %q; expected status %d", status, vo.String(), ve.String(), nativeStatus, no.String(), ne.String(), tc.status)
			}
			if tc.want != "" && !strings.Contains(vo.String(), tc.want) {
				t.Fatalf("missing expected output %q", tc.want)
			}
		})
	}
	t.Logf("same ELF verified natively and virtually: %d bytes, sha256 %x", len(image), sha256.Sum256(image))
}
