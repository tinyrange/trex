// Package im4p reads the ASN.1 IM4P firmware payload envelope. Payload bytes
// and optional DER metadata remain borrowed, without decryption/authentication.
package im4p

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

type Node struct {
	Tag      byte
	Data     storage.Reader
	Raw      storage.Reader
	Children []Node
}
type Image struct {
	Type, Description string
	Payload           storage.Reader
	Extras            []Node
	ExpectedSize      int64
}

func header(r storage.Reader, off, end int64) (byte, int64, int64, error) {
	var b [10]byte
	if off < 0 || off > end-2 {
		return 0, 0, 0, fmt.Errorf("im4p: truncated DER header")
	}
	if _, err := r.ReadAt(b[:2], off); err != nil {
		return 0, 0, 0, err
	}
	if b[0]&31 == 31 {
		return 0, 0, 0, fmt.Errorf("im4p: high DER tags unsupported")
	}
	n := int64(b[1])
	h := int64(2)
	if b[1]&128 != 0 {
		width := int64(b[1] & 127)
		if width == 0 || width > 8 || width > end-off-2 {
			return 0, 0, 0, fmt.Errorf("im4p: invalid DER length")
		}
		if _, err := r.ReadAt(b[2:2+width], off+2); err != nil {
			return 0, 0, 0, err
		}
		if b[2] == 0 {
			return 0, 0, 0, fmt.Errorf("im4p: noncanonical DER length")
		}
		n = 0
		for _, v := range b[2 : 2+width] {
			if n > (1<<63-1-int64(v))/256 {
				return 0, 0, 0, fmt.Errorf("im4p: length overflow")
			}
			n = n*256 + int64(v)
		}
		if n < 128 {
			return 0, 0, 0, fmt.Errorf("im4p: noncanonical DER length")
		}
		h += width
	}
	if n > end-off-h {
		return 0, 0, 0, fmt.Errorf("im4p: DER extent outside source")
	}
	return b[0], h, n, nil
}
func node(r storage.Reader, off, end int64, depth int, count *int) (Node, int64, error) {
	*count++
	if depth > 32 || *count > 1024 {
		return Node{}, 0, fmt.Errorf("im4p: DER nesting/node limit")
	}
	tag, h, n, err := header(r, off, end)
	if err != nil {
		return Node{}, 0, err
	}
	result := Node{Tag: tag, Data: io.NewSectionReader(r, off+h, n), Raw: io.NewSectionReader(r, off, h+n)}
	if tag&32 != 0 {
		for pos := off + h; pos < off+h+n; {
			child, next, err := node(r, pos, off+h+n, depth+1, count)
			if err != nil {
				return Node{}, 0, err
			}
			result.Children = append(result.Children, child)
			pos = next
		}
	}
	return result, off + h + n, nil
}
func text(n Node) (string, error) {
	if n.Tag != 0x16 || n.Data.Size() > 4096 {
		return "", fmt.Errorf("im4p: expected bounded IA5 string")
	}
	b := make([]byte, n.Data.Size())
	if _, err := io.ReadFull(io.NewSectionReader(n.Data, 0, n.Data.Size()), b); err != nil {
		return "", err
	}
	for _, c := range b {
		if c > 127 || c == 0 {
			return "", fmt.Errorf("im4p: invalid IA5 string")
		}
	}
	return string(b), nil
}
func integer(n Node) (int64, error) {
	size := n.Data.Size()
	if n.Tag != 2 || size <= 0 || size > 8 {
		return 0, fmt.Errorf("im4p: invalid integer")
	}
	var b [8]byte
	if _, err := n.Data.ReadAt(b[:size], 0); err != nil {
		return 0, err
	}
	if b[0]&128 != 0 || size > 1 && b[0] == 0 && b[1]&128 == 0 {
		return 0, fmt.Errorf("im4p: invalid positive integer")
	}
	v := int64(0)
	for _, c := range b[:size] {
		v = v*256 + int64(c)
	}
	return v, nil
}
func Open(r storage.Reader) (*Image, error) {
	if r == nil {
		return nil, fmt.Errorf("im4p: missing source")
	}
	count := 0
	root, end, err := node(r, 0, r.Size(), 0, &count)
	if err != nil {
		return nil, err
	}
	if end != r.Size() || root.Tag != 0x30 || len(root.Children) < 4 {
		return nil, fmt.Errorf("im4p: invalid envelope/trailing data")
	}
	children := root.Children
	magic, err := text(children[0])
	if err != nil || magic != "IM4P" {
		return nil, fmt.Errorf("im4p: missing IM4P signature")
	}
	kind, err := text(children[1])
	if err != nil || len(kind) != 4 {
		return nil, fmt.Errorf("im4p: invalid payload type")
	}
	desc, err := text(children[2])
	if err != nil {
		return nil, err
	}
	if children[3].Tag != 4 {
		return nil, fmt.Errorf("im4p: payload is not OCTET STRING")
	}
	image := &Image{Type: kind, Description: desc, Payload: children[3].Data, Extras: children[4:]}
	for _, extra := range image.Extras {
		if extra.Tag == 0x30 && len(extra.Children) == 2 && extra.Children[0].Tag == 2 && extra.Children[1].Tag == 2 {
			method, err := integer(extra.Children[0])
			if err != nil {
				return nil, err
			}
			size, err := integer(extra.Children[1])
			if err != nil {
				return nil, err
			}
			if method != 1 || size <= 0 || image.ExpectedSize != 0 {
				return nil, fmt.Errorf("im4p: invalid compression metadata")
			}
			image.ExpectedSize = size
		}
	}
	return image, nil
}
