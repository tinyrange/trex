package smb

import (
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// Config exports one filesystem over a private byte transport. Trace receives
// command/status metadata only, never credentials or file contents.
type Config struct {
	User, Domain, Password, Share string
	Files                         FileSystem
	Trace                         func(uint16, uint32)
	TraceCreate                   func(CreateTrace)
}

// CreateTrace contains only open-mode diagnostics, never paths or payloads.
type CreateTrace struct {
	Root                                        bool
	Access, Share, Disposition, Options, Status uint32
	OpenHandles                                 int
}

type Server struct {
	mu      sync.Mutex
	config  Config
	guid    [16]byte
	started time.Time
	streams map[io.ReadWriteCloser]bool
	closed  bool
	wg      sync.WaitGroup
}

// NewServer creates no host listener. The caller owns Files and closes it after
// Server.Close. Serve owns each supplied stream and closes it on return.
func NewServer(c Config) (*Server, error) {
	if c.Files == nil || c.User == "" || c.Password == "" || c.Share == "" || len(c.Share) > 80 || strings.ContainsAny(c.Share, `\/:*?"<>|`) {
		return nil, errors.New("invalid SMB configuration")
	}
	s := &Server{config: c, started: time.Now(), streams: make(map[io.ReadWriteCloser]bool)}
	if _, e := rand.Read(s.guid[:]); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Server) Serve(stream io.ReadWriteCloser) error {
	s.mu.Lock()
	if s.closed || len(s.streams) >= 32 {
		s.mu.Unlock()
		stream.Close()
		return errors.New("SMB closed or busy")
	}
	s.streams[stream] = true
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.streams, stream); s.mu.Unlock(); s.wg.Done() }()
	c, e := newSession(s.config.User, s.config.Domain, s.config.Password, s.guid, s.started)
	if e != nil {
		stream.Close()
		return e
	}
	c.files = s.config.Files
	c.share = s.config.Share
	c.trace = s.config.Trace
	c.traceCreate = s.config.TraceCreate
	c.handles = make(map[[16]byte]*openFile)
	return c.serve(stream)
}

// Close interrupts streams and waits for all open file handles to be released.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	streams := make([]io.ReadWriteCloser, 0, len(s.streams))
	for c := range s.streams {
		streams = append(streams, c)
	}
	s.mu.Unlock()
	for _, c := range streams {
		c.Close()
	}
	s.wg.Wait()
	return nil
}
