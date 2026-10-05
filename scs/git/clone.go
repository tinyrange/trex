// Package gitstore speaks Git upload-pack directly and resolves the transport
// into native SCS objects. No local Git executable or permanent pack/index is used.
package gitstore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

type Options struct {
	Name     string
	Auth     transport.AuthMethod
	Progress io.Writer
	// Zero means 256 MiB of transport data (held in bounded paged memory). Native storage is separately bounded.
	MaxPackBytes   int64
	MaxNativeBytes int64
	Transport      transport.Transport
}

// Download describes the verified wire transport and advertised refs, not a
// stored Git pack. Its pack stream is temporary decoder input only.
type Download struct {
	Remote       string            `json:"remote"`
	Head         string            `json:"head"`
	Refs         map[string]string `json:"refs"`
	SymbolicRefs map[string]string `json:"symbolic_refs"`
	Peeled       map[string]string `json:"peeled"`
	PackHash     string            `json:"pack_hash"`
	PackBytes    int64             `json:"pack_bytes"`
	Objects      uint32            `json:"objects"`
	Seconds      float64           `json:"receive_seconds"`
}

// ReceivePack requests all advertised refs, without depth/filter/thin-pack, and
// writes verified transport bytes to a caller-owned temporary spool. It does not
// write these bytes into the native repository.
func ReceivePack(ctx context.Context, url string, dst io.Writer, opt Options) (Download, error) {
	var result Download
	if opt.Progress == nil {
		opt.Progress = io.Discard
	}
	if opt.MaxPackBytes == 0 {
		opt.MaxPackBytes = 256 << 20
	}
	if opt.MaxPackBytes < 32 || opt.MaxPackBytes == math.MaxInt64 {
		return result, errors.New("invalid transport byte limit")
	}
	ep, err := transport.NewEndpoint(url)
	if err != nil {
		return result, err
	}
	switch ep.Protocol {
	case "https", "http", "git", "ssh":
	default:
		return result, errors.New("native clone requires http(s), git://, or ssh://")
	}
	tr := opt.Transport
	if tr == nil {
		return result, errors.New("Git transport must be supplied by a native backend")
	}
	session, err := tr.NewUploadPackSession(ep, opt.Auth)
	if err != nil {
		return result, err
	}
	defer session.Close()
	start := time.Now()
	adv, err := session.AdvertisedReferencesContext(ctx)
	if err != nil {
		return result, err
	}
	if len(adv.Shallows) > 0 {
		return result, errors.New("remote is shallow; full history unavailable")
	}
	for _, f := range adv.Capabilities.Get(capability.Capability("object-format")) {
		if f != "sha1" {
			return result, fmt.Errorf("Git wire object format %q is not yet supported", f)
		}
	}
	safe := *ep
	safe.User = ""
	safe.Password = ""
	result = Download{Remote: safe.String(), Refs: map[string]string{}, Peeled: map[string]string{}, SymbolicRefs: map[string]string{}}
	for n, h := range adv.References {
		result.Refs[n] = h.String()
	}
	for n, h := range adv.Peeled {
		result.Peeled[n] = h.String()
	}
	if adv.Head != nil {
		result.Head = adv.Head.String()
	}
	for _, s := range adv.Capabilities.Get(capability.SymRef) {
		for i := range s {
			if s[i] == ':' {
				result.SymbolicRefs[s[:i]] = s[i+1:]
				break
			}
		}
	}
	req := packp.NewUploadPackRequestFromCapabilities(adv.Capabilities)
	req.Capabilities.Delete(capability.ThinPack)
	seen := map[plumbing.Hash]bool{}
	for _, h := range adv.References {
		if h != plumbing.ZeroHash && !seen[h] {
			req.Wants = append(req.Wants, h)
			seen[h] = true
		}
	}
	if adv.Head != nil && *adv.Head != plumbing.ZeroHash && !seen[*adv.Head] {
		req.Wants = append(req.Wants, *adv.Head)
	}
	if len(req.Wants) == 0 {
		return result, errors.New("remote has no objects")
	}
	fmt.Fprintf(opt.Progress, "requesting full history: %d advertised refs, %d distinct tips\n", len(result.Refs), len(req.Wants))
	response, err := session.UploadPack(ctx, req)
	if err != nil {
		return result, err
	}
	defer response.Close()
	var src io.Reader = response
	if req.Capabilities.Supports(capability.Sideband64k) {
		d := sideband.NewDemuxer(sideband.Sideband64k, response)
		d.Progress = opt.Progress
		src = d
	} else if req.Capabilities.Supports(capability.Sideband) {
		d := sideband.NewDemuxer(sideband.Sideband, response)
		d.Progress = opt.Progress
		src = d
	}
	sum := &packDigest{h: sha1.New()}
	src = io.TeeReader(io.LimitReader(contextReader{ctx, src}, opt.MaxPackBytes+1), sum)
	buffered := bufio.NewReaderSize(src, 128<<10)
	h, err := buffered.Peek(12)
	if err != nil {
		return result, err
	}
	version := binary.BigEndian.Uint32(h[4:8])
	if string(h[:4]) != "PACK" || (version != 2 && version != 3) {
		return result, errors.New("invalid pack header")
	}
	result.Objects = binary.BigEndian.Uint32(h[8:12])
	if result.Objects > 100_000_000 {
		return result, errors.New("pack object count exceeds resource limit")
	}
	fmt.Fprintf(opt.Progress, "transport declares %d objects\n", result.Objects)
	n, err := io.CopyBuffer(dst, buffered, make([]byte, 1<<20))
	if err != nil {
		return result, err
	}
	if n > opt.MaxPackBytes {
		return result, errors.New("transport byte limit exceeded")
	}
	if sum.n < 32 || !bytes.Equal(sum.tail, sum.h.Sum(nil)) {
		return result, errors.New("Git pack checksum mismatch")
	}
	result.PackBytes = n
	result.PackHash = hex.EncodeToString(sum.tail)
	result.Seconds = time.Since(start).Seconds()
	fmt.Fprintf(opt.Progress, "received and verified %d transport bytes in %.1fs\n", n, result.Seconds)
	return result, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

type packDigest struct {
	h    hash.Hash
	tail []byte
	n    int64
}

func (p *packDigest) Write(b []byte) (int, error) {
	n := len(b)
	p.n += int64(n)
	if len(b) >= 20 {
		p.h.Write(p.tail)
		p.h.Write(b[:len(b)-20])
		p.tail = append(p.tail[:0], b[len(b)-20:]...)
	} else {
		p.tail = append(p.tail, b...)
		if len(p.tail) > 20 {
			p.h.Write(p.tail[:len(p.tail)-20])
			copy(p.tail, p.tail[len(p.tail)-20:])
			p.tail = p.tail[:20]
		}
	}
	return n, nil
}
