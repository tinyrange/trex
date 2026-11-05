package starlarkfrontend

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"hash"
	"io"
	"strings"
	"sync"
)

func digestHash(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "md5":
		return md5.New(), nil
	case "sha1", "sha-1":
		return sha1.New(), nil
	case "sha256", "sha-256":
		return sha256.New(), nil
	case "sha512", "sha-512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("digest: unsupported algorithm %q", algorithm)
	}
}

// digestManyBuiltin snapshots inputs on the interpreter thread. Workers only
// read portable byte readers; no Starlark evaluation or mutation runs in them.
func digestManyBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	algorithm := "sha256"
	workers := 4
	var whileRunning starlark.Value = starlark.None
	if err := starlark.UnpackArgs("digest_many", args, kwargs, "values", &values, "algorithm?", &algorithm, "workers?", &workers, "while_running?", &whileRunning); err != nil {
		return nil, err
	}
	if whileRunning != starlark.None {
		if _, ok := whileRunning.(starlark.Callable); !ok {
			return nil, fmt.Errorf("digest_many: while_running must be callable or None")
		}
	}
	if workers < 1 || workers > 8 || values.Len() > 65536 {
		return nil, fmt.Errorf("digest_many: requires 1..8 workers and at most 65536 values")
	}
	if _, err := digestHash(algorithm); err != nil {
		return nil, err
	}
	results := make([]starlark.Value, values.Len())
	inputs := make([]io.Reader, values.Len())
	identities := make([]starlark.Value, values.Len())
	sizes := make([]int64, len(inputs))
	for i := range inputs {
		value := values.Index(i)
		identities[i] = value
		if digest, ok := verifiedDigest(value, algorithm); ok {
			results[i] = digest
			continue
		}
		if file, ok := value.(File); ok {
			sizes[i] = file.Size()
			if sizes[i] < 0 {
				return nil, fmt.Errorf("digest_many: negative file size at %d", i)
			}
			inputs[i] = io.NewSectionReader(file, 0, sizes[i])
		} else {
			data, err := binaryapi.BytesForValue(value)
			if err != nil {
				return nil, fmt.Errorf("digest_many: values[%d]: %w", i, err)
			}
			sizes[i] = int64(len(data))
			inputs[i] = bytes.NewReader(data)
		}
	}
	errors := make([]error, len(inputs))
	jobs := make(chan int, len(inputs))
	for i := range inputs {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	for range min(workers, len(inputs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if results[i] != nil {
					continue
				}
				h, _ := digestHash(algorithm)
				// A lazy immutable reader may reconstruct and verify its entire
				// payload during the first read. Recheck its proven identity
				// before streaming that same content a second time. Ordinary
				// and mutable readers still hash every byte, including the
				// prefix, and short reads still fail the entire batch.
				prefix := min(sizes[i], int64(32<<10))
				if _, err := io.CopyN(h, inputs[i], prefix); err != nil {
					errors[i] = err
					continue
				}
				if digest, ok := verifiedDigest(identities[i], algorithm); ok {
					results[i] = digest
					continue
				}
				if _, err := io.CopyN(h, inputs[i], sizes[i]-prefix); err != nil {
					errors[i] = err
				} else {
					results[i] = starlark.Bytes(h.Sum(nil))
				}
			}
		}()
	}
	// The callback remains on the calling interpreter thread. Inputs were
	// captured above; it must not mutate their underlying content. Always join
	// native readers even if Starlark fails or the callback is interrupted.
	var callbackErr error
	if whileRunning != starlark.None {
		_, callbackErr = starlark.Call(thread, whileRunning, nil, nil)
	}
	wg.Wait()
	if callbackErr != nil {
		return nil, callbackErr
	}
	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("digest_many: values[%d]: %w", i, err)
		}
	}
	return starlark.NewList(results), nil
}

func verifiedDigest(value starlark.Value, algorithm string) (starlark.Value, bool) {
	if !strings.EqualFold(algorithm, "sha256") && !strings.EqualFold(algorithm, "sha-256") {
		return nil, false
	}
	if reader, ok := value.(storage.VerifiedSHA256Reader); ok {
		if digest, verified := reader.VerifiedSHA256(); verified {
			return starlark.Bytes(digest[:]), true
		}
	}
	return nil, false
}
