package qemu

import (
	"bytes"
	"io"
	"runtime"
	"testing"
)

type bootTestReader struct {
	*bytes.Reader
	size int64
}

func (r bootTestReader) Size() int64 { return r.size }

func TestAnonymousBootTransport(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux anonymous direct boot transport")
	}
	payload := []byte("kernel bytes with zero\x00and final byte")
	source := bootTestReader{bytes.NewReader(payload), int64(len(payload))}
	file, err := fileToMemfd("boot-test", source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("boot bytes = %q, err = %v", got, err)
	}
	truncated := bootTestReader{bytes.NewReader(payload), int64(len(payload) + 1)}
	if file, err := fileToMemfd("truncated-boot", truncated); err == nil {
		file.Close()
		t.Fatal("accepted truncated kernel/initramfs source")
	}
}
