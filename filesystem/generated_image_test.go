package filesystem

import (
	"bytes"
	"io"
	"testing"

	"github.com/tinyrange/trex/block"
)

type sparseTestWriter struct {
	position int64
	size     int64
	writes   int
}

func (w *sparseTestWriter) Write(p []byte) (int, error) {
	w.position += int64(len(p))
	if w.position > w.size {
		w.size = w.position
	}
	w.writes++
	return len(p), nil
}

func (w *sparseTestWriter) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		w.position = offset
	case io.SeekCurrent:
		w.position += offset
	case io.SeekEnd:
		w.position = w.size + offset
	}
	return w.position, nil
}

func TestGeneratedImageFileIndexesSparseExtents(t *testing.T) {
	image := &generatedImageFile{
		name: "sparse",
		size: 16,
		extents: []imageExtent{
			{start: 12, size: 2, data: []byte("CD")},
			{start: 3, size: 3, data: []byte("abc")},
			{start: 8, size: 2, data: []byte("AB")},
		},
	}

	got := make([]byte, 16)
	if n, err := image.ReadAt(got, 0); n != len(got) || err != nil {
		t.Fatalf("ReadAt() = %d, %v", n, err)
	}
	want := []byte{0, 0, 0, 'a', 'b', 'c', 0, 0, 'A', 'B', 0, 0, 'C', 'D', 0, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadAt() = %v, want %v", got, want)
	}
	if image.extents[0].start != 3 || image.extents[1].start != 8 || image.extents[2].start != 12 {
		t.Fatalf("extents were not indexed in offset order: %+v", image.extents)
	}

	tail := make([]byte, 4)
	if n, err := image.ReadAt(tail, 14); n != 2 || err != io.EOF {
		t.Fatalf("tail ReadAt() = %d, %v, want 2, EOF", n, err)
	}
}

func TestGeneratedImageFileRejectsInvalidExtents(t *testing.T) {
	tests := []struct {
		name    string
		extents []imageExtent
	}{
		{name: "overlap", extents: []imageExtent{{start: 2, size: 4}, {start: 5, size: 2}}},
		{name: "past end", extents: []imageExtent{{start: 9, size: 2}}},
		{name: "negative start", extents: []imageExtent{{start: -1, size: 1}}},
		{name: "short data", extents: []imageExtent{{start: 0, size: 2, data: []byte{1}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := &generatedImageFile{name: test.name, size: 10, extents: test.extents}
			if _, err := image.ReadAt(make([]byte, 1), 0); err == nil {
				t.Fatal("ReadAt() succeeded for invalid extents")
			}
			if _, err := image.WriteTo(io.Discard); err == nil {
				t.Fatal("WriteTo() succeeded for invalid extents")
			}
		})
	}
}

func TestGeneratedImageFilePropagatesNestedSparseExtents(t *testing.T) {
	filesystem := &generatedImageFile{
		name:    "filesystem",
		size:    8,
		extents: []imageExtent{{start: 2, size: 2, data: []byte{1, 2}}},
	}
	disk := &generatedImageFile{
		name:    "disk",
		size:    16,
		extents: []imageExtent{{start: 4, size: 8, file: filesystem}},
	}
	want := []block.Extent{
		{Offset: 0, Length: 6, Allocated: false},
		{Offset: 6, Length: 2, Allocated: true},
		{Offset: 8, Length: 8, Allocated: false},
	}
	got, err := disk.Extents(0, disk.Size())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("Extents() = %+v, want %+v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("Extents()[%d] = %+v, want %+v", index, got[index], want[index])
		}
	}

	device, err := block.NewFileDevice(disk, block.FileDeviceOptions{LogicalBlockSize: 512, PhysicalBlockSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	if !device.Capabilities().Extents {
		t.Fatal("file block device did not advertise sparse extents")
	}
	deviceExtents, err := device.Extents(0, disk.Size())
	if err != nil {
		t.Fatal(err)
	}
	if len(deviceExtents) != len(want) {
		t.Fatalf("block Extents() = %+v, want %+v", deviceExtents, want)
	}
}

func TestGeneratedImageFileWriteToExtendsTrailingSparseGap(t *testing.T) {
	image := &generatedImageFile{
		name:    "trailing-gap",
		size:    1 << 30,
		extents: []imageExtent{{start: 512, size: 3, data: []byte("MBR")}},
	}
	w := &sparseTestWriter{}
	written, err := image.WriteTo(w)
	if err != nil {
		t.Fatal(err)
	}
	if written != image.size || w.position != image.size || w.size != image.size {
		t.Fatalf("WriteTo() = %d bytes at position %d with size %d, want %d", written, w.position, w.size, image.size)
	}
	if w.writes != 3 {
		t.Fatalf("WriteTo() performed %d physical writes, want one per gap plus extent", w.writes)
	}
}

func BenchmarkGeneratedImageFileRandomRead(b *testing.B) {
	const (
		extentCount = 32768
		stride      = int64(4096)
	)
	extents := make([]imageExtent, extentCount)
	for i := range extents {
		extents[i] = imageExtent{
			start: int64(i) * stride,
			size:  512,
			data:  make([]byte, 512),
		}
	}
	image := &generatedImageFile{name: "benchmark", size: extentCount * stride, extents: extents}
	buffer := make([]byte, 4096)
	if _, err := image.ReadAt(buffer, 0); err != nil {
		b.Fatal(err)
	}
	b.Run("indexed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			offset := int64((uint64(i)*2654435761)%extentCount) * stride
			if _, err := image.ReadAt(buffer, offset); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("legacy-linear", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			offset := int64((uint64(i)*2654435761)%extentCount) * stride
			if _, err := legacyGeneratedImageReadAt(image, buffer, offset); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func legacyGeneratedImageReadAt(file *generatedImageFile, p []byte, off int64) (int, error) {
	remaining := int64(len(p))
	read := int64(0)
	for read < remaining {
		position := off + read
		count := remaining - read
		matched := false
		for _, extent := range file.extents {
			if position < extent.start || position >= extent.start+extent.size {
				continue
			}
			within := position - extent.start
			if available := extent.size - within; count > available {
				count = available
			}
			copy(p[read:read+count], extent.data[within:within+count])
			read += count
			matched = true
			break
		}
		if matched {
			continue
		}
		for _, extent := range file.extents {
			if extent.start > position && count > extent.start-position {
				count = extent.start - position
			}
		}
		clear(p[read : read+count])
		read += count
	}
	return int(read), nil
}
