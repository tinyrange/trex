package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

// faultFile writes a real prefix to the real file, then returns the injected
// error. Sync failure does not sync. durable records the last successful barrier
// so tests can independently reopen both the visible file and its durable image.
type faultFile struct {
	repositoryFile
	path          string
	remaining     int64 // -1: no write fault
	writeErr      error // nil intentionally models a contract-violating short writer
	failSync      int
	syncs, writes int
	writeSizes    []int
	hit           bool
	durable       []byte
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.writes++
	f.writeSizes = append(f.writeSizes, len(p))
	if f.remaining >= 0 && int64(len(p)) > f.remaining {
		count := int(f.remaining)
		f.remaining = -1
		f.hit = true
		if count > 0 {
			n, err := f.repositoryFile.Write(p[:count])
			if err != nil {
				return n, err
			}
		}
		return count, f.writeErr
	}
	if f.remaining >= 0 {
		f.remaining -= int64(len(p))
	}
	return f.repositoryFile.Write(p)
}
func (f *faultFile) Sync() error {
	f.syncs++
	if f.failSync == f.syncs {
		f.hit = true
		return syscall.EIO
	}
	if err := f.repositoryFile.Sync(); err != nil {
		return err
	}
	var err error
	f.durable, err = os.ReadFile(f.path)
	return err
}
func attachFault(t *testing.T, r *Repository, path string) *faultFile {
	t.Helper()
	must(t, r.flush())
	durable, err := os.ReadFile(path)
	must(t, err)
	f := &faultFile{repositoryFile: r.f, path: path, remaining: -1, durable: durable}
	r.f = f
	if r.writer != nil {
		r.writer.Reset(f)
	}
	return f
}
func failureBase(t *testing.T, mode string) ([]byte, ID) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "base.scs")
	createTestMode := createTestOptimized
	if mode == "v2" {
		createTestMode = createTest
	}
	r, err := createTestMode(path)
	must(t, err)
	w := r.Empty()
	must(t, w.WriteFile("f", []byte("old bytes")))
	id, err := w.Publish("main")
	must(t, err)
	_, err = w.Publish("sibling")
	must(t, err)
	if mode == "paged" {
		must(t, r.Checkpoint())
	}
	if mode == "legacy-checkpoint" {
		must(t, r.legacyCheckpoint())
	}
	must(t, r.Close())
	b, err := os.ReadFile(path)
	must(t, err)
	return b, id
}
func publishUpdate(w *Workspace) (ID, error) {
	if err := w.WriteFile("f", []byte("replacement bytes")); err != nil {
		return "", err
	}
	if err := w.Mkdir("new-dir"); err != nil {
		return "", err
	}
	if err := w.WriteFile("new-dir/output", bytes.Repeat([]byte("build-output"), 500)); err != nil {
		return "", err
	}
	if err := w.Symlink("link", "new-dir/output"); err != nil {
		return "", err
	}
	return w.Publish("main")
}
func assertRecovered(t *testing.T, path string, old, new ID, allowNew bool) {
	t.Helper()
	for _, open := range []func(string) (*Repository, error){openTest, openTestVerified} {
		r, err := open(path)
		must(t, err)
		refs := r.Refs()
		id := refs["main"]
		if refs["sibling"] != old || id != old && (!allowNew || id != new) {
			r.Close()
			t.Fatalf("unexpected recovered roots: %v", refs)
		}
		w, err := r.Checkout("main")
		must(t, err)
		paths, err := w.PathsWithError()
		must(t, err)
		if id == old {
			if len(paths) != 1 || paths[0] != "f" {
				t.Fatal("partial old root", paths)
			}
			readEquals(t, w, "f", []byte("old bytes"))
		} else {
			if len(paths) != 4 {
				t.Fatal("partial new root", paths)
			}
			readEquals(t, w, "f", []byte("replacement bytes"))
			readEquals(t, w, "new-dir/output", bytes.Repeat([]byte("build-output"), 500))
			target, err := w.Readlink("link")
			must(t, err)
			if target != "new-dir/output" {
				t.Fatal(target)
			}
		}
		must(t, r.Close())
	}
}
func TestStorageWriteAndSyncFailureRecovery(t *testing.T) {
	for _, mode := range []string{"v2", "v3", "paged", "legacy-checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			original, old := failureBase(t, mode)
			dir := t.TempDir()
			tracePath := filepath.Join(dir, "trace.scs")
			must(t, os.WriteFile(tracePath, original, 0600))
			r, err := openTest(tracePath)
			must(t, err)
			w, err := r.Checkout("main")
			must(t, err)
			trace := attachFault(t, r, tracePath)
			newID, err := publishUpdate(w)
			must(t, err)
			syncs := trace.syncs
			// Probe every physical write boundary and a midpoint in each write, plus
			// record-header edges. This includes buffered V3 and paged-index flushing.
			cuts := map[int64]bool{0: true, 1: true, headerSize - 1: true, headerSize: true, headerSize + 1: true}
			total := int64(0)
			for _, n := range trace.writeSizes {
				cuts[total] = true
				cuts[total+int64(n)/2] = true
				cuts[total+int64(n)-1] = true
				total += int64(n)
			}
			must(t, r.Close())
			var sorted []int64
			for cut := range cuts {
				if cut >= 0 && cut < total {
					sorted = append(sorted, cut)
				}
			}
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			for _, kind := range []string{"disk-full", "short-nil"} {
				for _, cut := range sorted {
					t.Run(fmt.Sprintf("%s/%d", kind, cut), func(t *testing.T) {
						path := filepath.Join(t.TempDir(), "r.scs")
						must(t, os.WriteFile(path, original, 0600))
						r, err := openTest(path)
						must(t, err)
						w, err := r.Checkout("main")
						must(t, err)
						f := attachFault(t, r, path)
						f.remaining = cut
						expected := error(io.ErrShortWrite)
						if kind == "disk-full" {
							f.writeErr = syscall.ENOSPC
							expected = syscall.ENOSPC
						}
						_, err = publishUpdate(w)
						if !f.hit || !errors.Is(err, expected) {
							t.Fatalf("fault not propagated: hit=%v error=%v", f.hit, err)
						}
						if r.Refs()["main"] != old {
							t.Fatal("failed publish moved in-memory root")
						}
						if err := w.WriteFile("later", []byte("must fail")); !errors.Is(err, expected) {
							t.Fatal("poisoned handle accepted write", err)
						}
						writes, syncs := f.writes, f.syncs
						if err := r.Close(); !errors.Is(err, expected) {
							t.Fatal("Close hid failure", err)
						}
						if f.writes != writes || f.syncs != syncs {
							t.Fatal("Close retried poisoned I/O")
						}
						assertRecovered(t, path, old, newID, true)
						durable := filepath.Join(t.TempDir(), "durable.scs")
						must(t, os.WriteFile(durable, f.durable, 0600))
						assertRecovered(t, durable, old, newID, false)
						// Recovery must permit subsequent writes through a fresh handle.
						recovered, err := openTest(path)
						must(t, err)
						live, err := recovered.Checkout("main")
						must(t, err)
						must(t, live.WriteFile("recovery", []byte("ok")))
						_, err = live.Publish("main")
						must(t, err)
						must(t, recovered.Close())
					})
				}
			}
			for barrier := 1; barrier <= syncs; barrier++ {
				t.Run(fmt.Sprintf("sync/%d", barrier), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "r.scs")
					must(t, os.WriteFile(path, original, 0600))
					r, err := openTest(path)
					must(t, err)
					w, err := r.Checkout("main")
					must(t, err)
					f := attachFault(t, r, path)
					f.failSync = barrier
					_, err = publishUpdate(w)
					if !f.hit || !errors.Is(err, syscall.EIO) {
						t.Fatal("missing sync failure", err)
					}
					if r.Refs()["main"] != old {
						t.Fatal("failed sync moved in-memory root")
					}
					writes := f.writes
					if err := r.Close(); !errors.Is(err, syscall.EIO) {
						t.Fatal("Close hid sync failure", err)
					}
					if f.writes != writes || f.syncs != barrier {
						t.Fatal("Close retried poisoned I/O")
					}
					// Failed fsync is ambiguous: page-cache bytes may contain the full new
					// root, while a simulated loss of unsynced bytes must retain the old root.
					assertRecovered(t, path, old, newID, true)
					durable := filepath.Join(t.TempDir(), "durable.scs")
					must(t, os.WriteFile(durable, f.durable, 0600))
					assertRecovered(t, durable, old, newID, false)
				})
			}
		})
	}
}
