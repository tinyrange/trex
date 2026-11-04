package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

type offlineTrapTransport struct{ t *testing.T }

func (x offlineTrapTransport) RoundTrip(*http.Request) (*http.Response, error) {
	x.t.Error("offline reader attempted HTTP")
	return nil, fmt.Errorf("network forbidden")
}
func TestOfflineRangePoolHitsMissesAndCorruptionNeverUseNetwork(t *testing.T) {
	disk, err := NewHTTPRangeDiskCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abcdefgh")
	sum := sha256.Sum256(data)
	identity := hex.EncodeToString(sum[:])
	if _, err := disk.get(context.Background(), sum, 8, 0, 4, func() ([]byte, error) { return data[:4], nil }); err != nil {
		t.Fatal(err)
	}
	for _, urls := range [][]string{nil, {"https://must-not-be-contacted.invalid/payload"}} {
		pool, err := NewOfflineHTTPRangePool(4, 4, disk)
		if err != nil {
			t.Fatal(err)
		}
		pool.client = &http.Client{Transport: offlineTrapTransport{t}}
		pool.resolveLocations = func(context.Context, string, int64, []string) ([]string, error) {
			t.Error("offline reader resolved URLs")
			return nil, fmt.Errorf("forbidden")
		}
		f, err := pool.OpenSHA256(context.Background(), "payload.esd", urls, 8, identity)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := f.ReadAt(b, 0); err != nil || !bytes.Equal(b, data[:4]) {
			t.Fatalf("cache hit: %q %v", b, err)
		}
		// The miss occurs after a successful read, as with a deferred boot read.
		if _, err := f.ReadAt(b, 4); err == nil || !strings.Contains(err.Error(), "offline payload cache miss") {
			t.Fatalf("miss: %v", err)
		}
		if _, err := pool.Discover(context.Background(), "size", urls); err == nil {
			t.Fatal("offline discovery allowed")
		}
	}
	name := disk.blockPath(sum, 8, 0, 4)
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	pool, _ := NewOfflineHTTPRangePool(4, 4, disk)
	pool.client = &http.Client{Transport: offlineTrapTransport{t}}
	f, err := pool.OpenSHA256(context.Background(), "payload.esd", nil, 8, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(make([]byte, 4), 0); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corruption: %v", err)
	}
}
