package nbd

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	blockpkg "github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	channelpkg "github.com/tinyrange/trex/channel"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

const DefaultMaxRequest = nbdDefaultMaxRequest

type blockDeviceLease interface {
	Acquire() (func(), error)
}

const (
	nbdMagic             = uint64(0x4e42444d41474943)
	nbdOptionsMagic      = uint64(0x49484156454f5054)
	nbdOptionReplyMagic  = uint64(0x0003e889045565a9)
	nbdRequestMagic      = uint32(0x25609513)
	nbdSimpleReplyMagic  = uint32(0x67446698)
	nbdStructuredMagic   = uint32(0x668e33ef)
	nbdMaxOptionSize     = 1 << 20
	nbdMaxExportName     = 4096
	nbdDefaultMaxRequest = 8 << 20
	nbdDefaultWorkers    = 4

	nbdFlagFixedNewstyle = uint16(1 << 0)
	nbdFlagNoZeroes      = uint16(1 << 1)

	nbdClientFixedNewstyle = uint32(1 << 0)
	nbdClientNoZeroes      = uint32(1 << 1)

	nbdOptExportName      = uint32(1)
	nbdOptAbort           = uint32(2)
	nbdOptList            = uint32(3)
	nbdOptStartTLS        = uint32(5)
	nbdOptInfo            = uint32(6)
	nbdOptGo              = uint32(7)
	nbdOptStructuredReply = uint32(8)
	nbdOptListMetaContext = uint32(9)
	nbdOptSetMetaContext  = uint32(10)

	nbdRepACK         = uint32(1)
	nbdRepServer      = uint32(2)
	nbdRepInfo        = uint32(3)
	nbdRepMetaContext = uint32(4)
	nbdRepErrUnsup    = uint32(0x80000001)
	nbdRepErrInvalid  = uint32(0x80000003)
	nbdRepErrUnknown  = uint32(0x80000006)
	nbdRepErrTooBig   = uint32(0x80000009)

	nbdInfoExport    = uint16(0)
	nbdInfoName      = uint16(1)
	nbdInfoBlockSize = uint16(3)

	nbdTransmissionHasFlags      = uint16(1 << 0)
	nbdTransmissionReadOnly      = uint16(1 << 1)
	nbdTransmissionSendFlush     = uint16(1 << 2)
	nbdTransmissionSendFUA       = uint16(1 << 3)
	nbdTransmissionSendTrim      = uint16(1 << 5)
	nbdTransmissionSendWriteZero = uint16(1 << 6)
	nbdTransmissionSendDF        = uint16(1 << 7)
	nbdTransmissionCanMultiConn  = uint16(1 << 8)
	nbdTransmissionSendCache     = uint16(1 << 10)
	nbdTransmissionSendFastZero  = uint16(1 << 11)

	nbdCommandRead        = uint16(0)
	nbdCommandWrite       = uint16(1)
	nbdCommandDisconnect  = uint16(2)
	nbdCommandFlush       = uint16(3)
	nbdCommandTrim        = uint16(4)
	nbdCommandCache       = uint16(5)
	nbdCommandWriteZeroes = uint16(6)
	nbdCommandBlockStatus = uint16(7)

	nbdCommandFlagFUA      = uint16(1 << 0)
	nbdCommandFlagNoHole   = uint16(1 << 1)
	nbdCommandFlagDF       = uint16(1 << 2)
	nbdCommandFlagReqOne   = uint16(1 << 3)
	nbdCommandFlagFastZero = uint16(1 << 4)

	nbdStructuredDone        = uint16(1 << 0)
	nbdStructuredOffsetData  = uint16(1)
	nbdStructuredBlockStatus = uint16(5)
	nbdStructuredError       = uint16(0x8001)

	nbdStateHole = uint32(1 << 0)
	nbdStateZero = uint32(1 << 1)

	nbdErrPerm     = uint32(1)
	nbdErrIO       = uint32(5)
	nbdErrNoSpace  = uint32(28)
	nbdErrInvalid  = uint32(22)
	nbdErrOverflow = uint32(75)
	nbdErrNotSup   = uint32(95)
)

type nbdRequest struct {
	flags  uint16
	kind   uint16
	cookie uint64
	offset uint64
	length uint32
	data   []byte
}

// NBDServer exports a blockpkg.Device over a caller-owned byte channel. The
// server implements protocol framing itself and never uses a host NBD tool.
type NBDServer struct {
	device           blockpkg.Device
	exportName       string
	maxRequest       uint32
	structured       bool
	handshakeTimeout time.Duration
	requestTimeout   time.Duration
	workers          int
	buffers          chan []byte

	connections atomic.Uint64
	reads       atomic.Uint64
	writes      atomic.Uint64
	readBytes   atomic.Uint64
	writeBytes  atomic.Uint64
	flushes     atomic.Uint64
	zeroes      atomic.Uint64
	trims       atomic.Uint64
	cacheHints  atomic.Uint64
	commandErrs atomic.Uint64
	errors      atomic.Uint64
	requestsNS  atomic.Uint64
	bufferNew   atomic.Uint64
	bufferReuse atomic.Uint64
	active      atomic.Int64
	peakActive  atomic.Int64
	metrics     *lifecycle.Metrics

	errorMu   sync.RWMutex
	lastError string
}

// NBDStats is a point-in-time snapshot of an NBDServer. It contains only Go
// values so callers do not need the Starlark runtime to observe a server.
type NBDStats struct {
	Connections    uint64
	ActiveRequests int64
	BufferNew      uint64
	BufferReuse    uint64
	CacheHints     uint64
	CommandErrors  uint64
	Errors         uint64
	Flushes        uint64
	ReadBytes      uint64
	Reads          uint64
	RequestTimeNS  uint64
	PeakRequests   int64
	LastError      string
	Workers        int
	Trims          uint64
	WriteBytes     uint64
	WriteZeroes    uint64
	Writes         uint64
}

func NewNBDServer(device blockpkg.Device, exportName string, maxRequest uint32) (*NBDServer, error) {
	if device == nil {
		return nil, fmt.Errorf("nbd: device is required")
	}
	if len(exportName) > nbdMaxExportName || strings.IndexByte(exportName, 0) >= 0 {
		return nil, fmt.Errorf("nbd: invalid export name")
	}
	if maxRequest == 0 || maxRequest > nbdDefaultMaxRequest {
		return nil, fmt.Errorf("nbd: max_request must be between 1 and %d", nbdDefaultMaxRequest)
	}
	geometry := device.Geometry()
	if geometry.Size < 0 || geometry.Size > math.MaxInt64 {
		return nil, fmt.Errorf("nbd: invalid device size")
	}
	if geometry.MinimumTransfer == 0 || maxRequest < geometry.MinimumTransfer {
		return nil, fmt.Errorf("nbd: max_request is smaller than the minimum transfer")
	}
	return &NBDServer{
		device:           device,
		exportName:       exportName,
		maxRequest:       maxRequest,
		structured:       true,
		handshakeTimeout: 10 * time.Second,
		requestTimeout:   30 * time.Second,
		workers:          nbdDefaultWorkers,
		buffers:          make(chan []byte, nbdDefaultWorkers),
	}, nil
}

func (s *NBDServer) SetMetrics(metrics *lifecycle.Metrics) { s.metrics = metrics }
func (s *NBDServer) Device() blockpkg.Device               { return s.device }

func Builtin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	exportName := ""
	maxRequest := nbdDefaultMaxRequest
	structured := true
	handshakeTimeout := 10
	requestTimeout := 30
	workers := nbdDefaultWorkers
	if err := starlark.UnpackArgs("nbd", args, kwargs,
		"device", &value,
		"export_name?", &exportName,
		"max_request?", &maxRequest,
		"structured?", &structured,
		"handshake_timeout?", &handshakeTimeout,
		"request_timeout?", &requestTimeout,
		"workers?", &workers,
	); err != nil {
		return nil, err
	}
	device, err := blockstar.AsDevice(value)
	if err != nil {
		return nil, fmt.Errorf("nbd: device: %w", err)
	}
	if maxRequest <= 0 || maxRequest > nbdDefaultMaxRequest || handshakeTimeout <= 0 || requestTimeout <= 0 || workers <= 0 || workers > 64 {
		return nil, fmt.Errorf("nbd: invalid request limit or timeout")
	}
	server, err := NewNBDServer(device, exportName, uint32(maxRequest))
	if err != nil {
		return nil, err
	}
	server.structured = structured
	server.handshakeTimeout = time.Duration(handshakeTimeout) * time.Second
	server.requestTimeout = time.Duration(requestTimeout) * time.Second
	server.workers = workers
	server.buffers = make(chan []byte, workers)
	if resources, resourceErr := lifecycle.ForThread(thread); resourceErr == nil {
		server.metrics = resources.Metrics()
	}
	return &nbdServerValue{server: server}, nil
}

type nbdServerValue struct {
	server *NBDServer
	mu     sync.Mutex
	cancel context.CancelFunc
	active bool
}

func (v *nbdServerValue) String() string {
	return fmt.Sprintf("<nbd_server export=%q>", v.server.exportName)
}
func (v *nbdServerValue) Type() string          { return "nbd_server" }
func (v *nbdServerValue) Freeze()               {}
func (v *nbdServerValue) Truth() starlark.Bool  { return starlark.True }
func (v *nbdServerValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *nbdServerValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "serve":
		return starlark.NewBuiltin("serve", v.serveBuiltin), nil
	case "close":
		return starlark.NewBuiltin("close", v.closeBuiltin), nil
	case "stats":
		return starvalue.NewRecord(StatsStarlark(v.server.Stats())), nil
	case "export_name":
		return starlark.String(v.server.exportName), nil
	}
	return nil, nil
}
func (v *nbdServerValue) AttrNames() []string {
	return []string{"close", "export_name", "serve", "stats"}
}

func (v *nbdServerValue) serveBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var channelValue starlark.Value
	if err := starlark.UnpackArgs("serve", args, kwargs, "channel", &channelValue); err != nil {
		return nil, err
	}
	channel, ok := channelValue.(*channelstar.Value)
	if !ok {
		return nil, fmt.Errorf("serve: got %s, want byte_channel", channelValue.Type())
	}
	v.mu.Lock()
	if v.active {
		v.mu.Unlock()
		return nil, fmt.Errorf("serve: server already has an active connection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	v.cancel, v.active = cancel, true
	v.mu.Unlock()
	err := v.server.Serve(ctx, channel)
	v.mu.Lock()
	v.cancel, v.active = nil, false
	v.mu.Unlock()
	cancel()
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}
	return starlark.None, nil
}

func (v *nbdServerValue) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
		return nil, err
	}
	v.mu.Lock()
	cancel := v.cancel
	v.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return starlark.None, nil
}

// Stats returns a point-in-time snapshot of server activity.
func (s *NBDServer) Stats() NBDStats {
	s.errorMu.RLock()
	lastError := s.lastError
	s.errorMu.RUnlock()
	return NBDStats{
		Connections:    s.connections.Load(),
		ActiveRequests: s.active.Load(),
		BufferNew:      s.bufferNew.Load(),
		BufferReuse:    s.bufferReuse.Load(),
		CacheHints:     s.cacheHints.Load(),
		CommandErrors:  s.commandErrs.Load(),
		Errors:         s.errors.Load(),
		Flushes:        s.flushes.Load(),
		ReadBytes:      s.readBytes.Load(),
		Reads:          s.reads.Load(),
		RequestTimeNS:  s.requestsNS.Load(),
		PeakRequests:   s.peakActive.Load(),
		LastError:      lastError,
		Workers:        s.workers,
		Trims:          s.trims.Load(),
		WriteBytes:     s.writeBytes.Load(),
		WriteZeroes:    s.zeroes.Load(),
		Writes:         s.writes.Load(),
	}
}

func StatsStarlark(stats NBDStats) starlark.StringDict {
	return starlark.StringDict{
		"connections":     starlark.MakeUint64(stats.Connections),
		"active_requests": starlark.MakeInt64(stats.ActiveRequests),
		"buffer_new":      starlark.MakeUint64(stats.BufferNew),
		"buffer_reuse":    starlark.MakeUint64(stats.BufferReuse),
		"cache_hints":     starlark.MakeUint64(stats.CacheHints),
		"command_errors":  starlark.MakeUint64(stats.CommandErrors),
		"errors":          starlark.MakeUint64(stats.Errors),
		"flushes":         starlark.MakeUint64(stats.Flushes),
		"read_bytes":      starlark.MakeUint64(stats.ReadBytes),
		"reads":           starlark.MakeUint64(stats.Reads),
		"request_time_ns": starlark.MakeUint64(stats.RequestTimeNS),
		"peak_requests":   starlark.MakeInt64(stats.PeakRequests),
		"last_error":      starlark.String(stats.LastError),
		"workers":         starlark.MakeInt(stats.Workers),
		"trims":           starlark.MakeUint64(stats.Trims),
		"write_bytes":     starlark.MakeUint64(stats.WriteBytes),
		"write_zeroes":    starlark.MakeUint64(stats.WriteZeroes),
		"writes":          starlark.MakeUint64(stats.Writes),
	}
}

func (s *NBDServer) commandError(wire *nbdWire, request nbdRequest, state nbdNegotiationState, errno uint32, message string) error {
	s.commandErrs.Add(1)
	s.errorMu.Lock()
	s.lastError = fmt.Sprintf(
		"command=%d flags=%#x offset=%d length=%d errno=%d: %s",
		request.kind,
		request.flags,
		request.offset,
		request.length,
		errno,
		message,
	)
	s.errorMu.Unlock()
	return wire.commandError(request, state, errno, message)
}

func (s *NBDServer) Serve(ctx context.Context, channel channelpkg.ByteChannel) error {
	if channel == nil {
		return fmt.Errorf("nbd: channel is required")
	}
	release := func() {}
	if device, ok := s.device.(blockDeviceLease); ok {
		var err error
		release, err = device.Acquire()
		if err != nil {
			return err
		}
	}
	defer release()
	defer channel.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = channel.Close()
		case <-done:
		}
	}()
	defer close(done)

	s.connections.Add(1)
	wire := &nbdWire{reader: bufio.NewReaderSize(channel, 64<<10), writer: bufio.NewWriterSize(channel, 64<<10)}
	setByteChannelDeadline(channel, s.handshakeTimeout)
	state, err := s.negotiate(wire)
	if err != nil {
		s.errors.Add(1)
		return err
	}
	setByteChannelDeadline(channel, 0)
	if state.abort {
		return nil
	}
	return s.transmit(ctx, channel, wire, state)
}

type nbdNegotiationState struct {
	structured bool
	allocation bool
	noZeroes   bool
	abort      bool
}

func (s *NBDServer) negotiate(wire *nbdWire) (nbdNegotiationState, error) {
	var state nbdNegotiationState
	if err := wire.writeValues(nbdMagic, nbdOptionsMagic, nbdFlagFixedNewstyle|nbdFlagNoZeroes); err != nil {
		return state, err
	}
	var clientFlags uint32
	if err := wire.read(&clientFlags); err != nil {
		return state, err
	}
	if clientFlags&nbdClientFixedNewstyle == 0 || clientFlags&^(nbdClientFixedNewstyle|nbdClientNoZeroes) != 0 {
		return state, fmt.Errorf("nbd: unsupported client handshake flags %#x", clientFlags)
	}
	state.noZeroes = clientFlags&nbdClientNoZeroes != 0

	for {
		var magic uint64
		var option, length uint32
		if err := wire.read(&magic, &option, &length); err != nil {
			return state, err
		}
		if magic != nbdOptionsMagic {
			return state, fmt.Errorf("nbd: invalid option magic %#x", magic)
		}
		if length > nbdMaxOptionSize {
			_ = wire.optionReply(option, nbdRepErrTooBig, nil)
			return state, fmt.Errorf("nbd: option payload exceeds %d bytes", nbdMaxOptionSize)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(wire.reader, data); err != nil {
			return state, err
		}
		switch option {
		case nbdOptAbort:
			if length != 0 {
				if err := wire.optionReply(option, nbdRepErrInvalid, nil); err != nil {
					return state, err
				}
				continue
			}
			if err := wire.optionReply(option, nbdRepACK, nil); err != nil {
				return state, err
			}
			state.abort = true
			return state, nil
		case nbdOptList:
			if length != 0 {
				if err := wire.optionReply(option, nbdRepErrInvalid, nil); err != nil {
					return state, err
				}
				continue
			}
			payload := make([]byte, 4+len(s.exportName))
			binary.BigEndian.PutUint32(payload, uint32(len(s.exportName)))
			copy(payload[4:], s.exportName)
			if err := wire.optionReply(option, nbdRepServer, payload); err != nil {
				return state, err
			}
			if err := wire.optionReply(option, nbdRepACK, nil); err != nil {
				return state, err
			}
		case nbdOptStructuredReply:
			if length != 0 {
				if err := wire.optionReply(option, nbdRepErrInvalid, nil); err != nil {
					return state, err
				}
				continue
			}
			if !s.structured {
				if err := wire.optionReply(option, nbdRepErrUnsup, nil); err != nil {
					return state, err
				}
				continue
			}
			state.structured = true
			if err := wire.optionReply(option, nbdRepACK, nil); err != nil {
				return state, err
			}
		case nbdOptListMetaContext, nbdOptSetMetaContext:
			queries, name, err := parseNBDMetaContextRequest(data)
			if err != nil || name != s.exportName || !state.structured {
				if err := wire.optionReply(option, nbdRepErrInvalid, nil); err != nil {
					return state, err
				}
				continue
			}
			matched := false
			for _, query := range queries {
				if query == "base:" || query == "base:allocation" {
					payload := make([]byte, 4+len("base:allocation"))
					binary.BigEndian.PutUint32(payload, 1)
					copy(payload[4:], "base:allocation")
					if err := wire.optionReply(option, nbdRepMetaContext, payload); err != nil {
						return state, err
					}
					matched = true
					break
				}
			}
			if option == nbdOptSetMetaContext {
				state.allocation = matched
			}
			if err := wire.optionReply(option, nbdRepACK, nil); err != nil {
				return state, err
			}
		case nbdOptInfo, nbdOptGo:
			name, requests, err := parseNBDInfoRequest(data)
			if err != nil {
				if err := wire.optionReply(option, nbdRepErrInvalid, nil); err != nil {
					return state, err
				}
				continue
			}
			if name != s.exportName {
				if err := wire.optionReply(option, nbdRepErrUnknown, nil); err != nil {
					return state, err
				}
				continue
			}
			if err := s.writeInfoReplies(wire, option, requests, state); err != nil {
				return state, err
			}
			if option == nbdOptGo {
				return state, nil
			}
		case nbdOptExportName:
			if string(data) != s.exportName {
				return state, fmt.Errorf("nbd: unknown export %q", string(data))
			}
			if err := wire.writeValues(uint64(s.device.Geometry().Size), s.transmissionFlags(state)); err != nil {
				return state, err
			}
			if !state.noZeroes {
				if err := wire.writeBytes(make([]byte, 124)); err != nil {
					return state, err
				}
			}
			return state, nil
		case nbdOptStartTLS:
			if err := wire.optionReply(option, nbdRepErrUnsup, nil); err != nil {
				return state, err
			}
		default:
			if err := wire.optionReply(option, nbdRepErrUnsup, nil); err != nil {
				return state, err
			}
		}
	}
}

func (s *NBDServer) writeInfoReplies(wire *nbdWire, option uint32, requests []uint16, state nbdNegotiationState) error {
	wantBlockSize, wantName := false, false
	for _, request := range requests {
		switch request {
		case nbdInfoBlockSize:
			wantBlockSize = true
		case nbdInfoName:
			wantName = true
		}
	}
	export := make([]byte, 12)
	binary.BigEndian.PutUint16(export, nbdInfoExport)
	binary.BigEndian.PutUint64(export[2:], uint64(s.device.Geometry().Size))
	binary.BigEndian.PutUint16(export[10:], s.transmissionFlags(state))
	if err := wire.optionReply(option, nbdRepInfo, export); err != nil {
		return err
	}
	if wantName {
		payload := make([]byte, 2+len(s.exportName))
		binary.BigEndian.PutUint16(payload, nbdInfoName)
		copy(payload[2:], s.exportName)
		if err := wire.optionReply(option, nbdRepInfo, payload); err != nil {
			return err
		}
	}
	if wantBlockSize {
		geometry := s.device.Geometry()
		payload := make([]byte, 14)
		binary.BigEndian.PutUint16(payload, nbdInfoBlockSize)
		binary.BigEndian.PutUint32(payload[2:], geometry.MinimumTransfer)
		binary.BigEndian.PutUint32(payload[6:], geometry.PreferredTransfer)
		maximum := geometry.MaximumTransfer
		if maximum == 0 || maximum > s.maxRequest {
			maximum = s.maxRequest
		}
		binary.BigEndian.PutUint32(payload[10:], maximum)
		if err := wire.optionReply(option, nbdRepInfo, payload); err != nil {
			return err
		}
	}
	return wire.optionReply(option, nbdRepACK, nil)
}

func (s *NBDServer) transmissionFlags(state nbdNegotiationState) uint16 {
	capabilities := s.device.Capabilities()
	flags := nbdTransmissionHasFlags
	if !capabilities.Writable {
		flags |= nbdTransmissionReadOnly
	}
	if capabilities.Flush {
		flags |= nbdTransmissionSendFlush | nbdTransmissionSendFUA
	}
	if capabilities.Trim {
		flags |= nbdTransmissionSendTrim
	}
	if capabilities.Zero {
		flags |= nbdTransmissionSendWriteZero | nbdTransmissionSendFastZero
	}
	if capabilities.Prefetch {
		flags |= nbdTransmissionSendCache
	}
	if state.structured {
		flags |= nbdTransmissionSendDF
	}
	return flags
}

func (s *NBDServer) transmit(ctx context.Context, channel channelpkg.ByteChannel, wire *nbdWire, state nbdNegotiationState) error {
	type requestJob struct {
		request nbdRequest
		started time.Time
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	readJobs := make(chan requestJob, s.workers)
	fatal := make(chan error, 1)
	var jobs sync.WaitGroup
	var workers sync.WaitGroup

	run := func(queue <-chan requestJob) {
		defer workers.Done()
		failed := false
		for job := range queue {
			if failed {
				if job.request.data != nil {
					s.releaseBuffer(job.request.data)
				}
				jobs.Done()
				continue
			}
			s.requestStarted()
			err := s.handleRequest(wire, job.request, state)
			s.requestFinished(job.started)
			if job.request.data != nil {
				s.releaseBuffer(job.request.data)
			}
			jobs.Done()
			if err != nil {
				s.errors.Add(1)
				select {
				case fatal <- err:
				default:
				}
				cancel()
				_ = channel.Close()
				failed = true
			}
		}
	}
	workers.Add(s.workers)
	for range s.workers {
		go run(readJobs)
	}

	var readErr error
	loop := true
	for loop {
		if err := workerCtx.Err(); err != nil {
			readErr = err
			break
		}
		request, err := wire.readRequest(channel, s.requestTimeout)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
		if request.kind == nbdCommandDisconnect {
			break
		}
		if request.kind == nbdCommandWrite {
			if request.length > s.maxRequest {
				readErr = fmt.Errorf("nbd: oversized write payload %d", request.length)
				break
			}
			request.data = s.acquireBuffer(int(request.length))
			if _, err := io.ReadFull(wire.reader, request.data); err != nil {
				s.releaseBuffer(request.data)
				readErr = err
				break
			}
		}
		job := requestJob{request: request, started: time.Now()}
		if nbdMutationBarrier(request.kind) {
			// Mutations form barriers between concurrent read batches. Waiting
			// before execution prevents a later read from overtaking a write,
			// and not parsing another request until completion preserves flush
			// and FUA ordering without serializing independent reads.
			jobs.Wait()
			if err := workerCtx.Err(); err != nil {
				if request.data != nil {
					s.releaseBuffer(request.data)
				}
				readErr = err
				break
			}
			s.requestStarted()
			err := s.handleRequest(wire, request, state)
			s.requestFinished(job.started)
			if request.data != nil {
				s.releaseBuffer(request.data)
			}
			if err != nil {
				s.errors.Add(1)
				readErr = err
				break
			}
			continue
		}
		jobs.Add(1)
		select {
		case readJobs <- job:
		case <-workerCtx.Done():
			jobs.Done()
			readErr = workerCtx.Err()
			loop = false
		}
	}
	close(readJobs)
	jobs.Wait()
	workers.Wait()
	select {
	case err := <-fatal:
		return err
	default:
	}
	if errors.Is(readErr, context.Canceled) && ctx.Err() == nil {
		return nil
	}
	return readErr
}

func nbdMutationBarrier(kind uint16) bool {
	switch kind {
	case nbdCommandWrite, nbdCommandFlush, nbdCommandTrim, nbdCommandWriteZeroes:
		return true
	default:
		return false
	}
}

func (s *NBDServer) requestStarted() {
	active := s.active.Add(1)
	for {
		peak := s.peakActive.Load()
		if active <= peak || s.peakActive.CompareAndSwap(peak, active) {
			return
		}
	}
}

func (s *NBDServer) requestFinished(started time.Time) {
	s.active.Add(-1)
	s.requestsNS.Add(uint64(time.Since(started)))
}

func (s *NBDServer) acquireBuffer(length int) []byte {
	select {
	case buffer := <-s.buffers:
		s.bufferReuse.Add(1)
		if cap(buffer) >= length {
			return buffer[:length]
		}
	default:
	}
	s.bufferNew.Add(1)
	return make([]byte, length)
}

func (s *NBDServer) releaseBuffer(buffer []byte) {
	if cap(buffer) > int(s.maxRequest) {
		return
	}
	select {
	case s.buffers <- buffer[:0]:
	default:
	}
}

func (s *NBDServer) handleRequest(wire *nbdWire, request nbdRequest, state nbdNegotiationState) error {
	if request.length > s.maxRequest {
		return s.commandError(wire, request, state, nbdErrOverflow, "request exceeds maximum transfer")
	}
	length := int64(request.length)
	if request.kind != nbdCommandFlush && (request.length == 0 || !s.aligned(request.offset, request.length)) {
		return s.commandError(wire, request, state, nbdErrInvalid, "unaligned or empty request")
	}
	if request.kind != nbdCommandFlush && (request.offset > math.MaxInt64 || blockpkg.ValidateRange(s.device.Geometry().Size, int64(request.offset), length) != nil) {
		return s.commandError(wire, request, state, nbdErrInvalid, "request exceeds export")
	}

	switch request.kind {
	case nbdCommandRead:
		if request.flags & ^nbdCommandFlagDF != 0 || request.flags&nbdCommandFlagDF != 0 && !state.structured {
			return s.commandError(wire, request, state, nbdErrInvalid, "invalid read flags")
		}
		data := s.acquireBuffer(int(request.length))
		defer s.releaseBuffer(data)
		if _, err := s.device.ReadAt(data, int64(request.offset)); err != nil {
			return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
		}
		s.reads.Add(1)
		s.readBytes.Add(uint64(len(data)))
		if s.metrics != nil {
			s.metrics.NBDReadBytes.Add(uint64(len(data)))
		}
		if state.structured {
			payload := make([]byte, 8+len(data))
			binary.BigEndian.PutUint64(payload, request.offset)
			copy(payload[8:], data)
			return wire.structuredReply(request.cookie, nbdStructuredDone, nbdStructuredOffsetData, payload)
		}
		return wire.simpleReply(request.cookie, 0, data)

	case nbdCommandWrite:
		data := request.data
		if len(data) != int(request.length) {
			return fmt.Errorf("nbd: missing write payload")
		}
		if request.flags & ^nbdCommandFlagFUA != 0 {
			return s.commandError(wire, request, state, nbdErrInvalid, "invalid write flags")
		}
		writer, ok := s.device.(blockpkg.Writer)
		if !ok || !s.device.Capabilities().Writable {
			return s.commandError(wire, request, state, nbdErrPerm, blockpkg.ErrReadOnly.Error())
		}
		if _, err := writer.WriteAt(data, int64(request.offset)); err != nil {
			return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
		}
		if request.flags&nbdCommandFlagFUA != 0 {
			if err := s.flush(); err != nil {
				return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
			}
		}
		s.writes.Add(1)
		s.writeBytes.Add(uint64(len(data)))
		if s.metrics != nil {
			s.metrics.NBDWriteBytes.Add(uint64(len(data)))
		}
		return wire.commandDone(request, state)

	case nbdCommandFlush:
		if request.flags != 0 || request.offset != 0 || request.length != 0 {
			return s.commandError(wire, request, state, nbdErrInvalid, "invalid flush request")
		}
		if err := s.flush(); err != nil {
			return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
		}
		s.flushes.Add(1)
		return wire.commandDone(request, state)

	case nbdCommandWriteZeroes:
		if request.flags & ^(nbdCommandFlagFUA|nbdCommandFlagNoHole|nbdCommandFlagFastZero) != 0 {
			return s.commandError(wire, request, state, nbdErrInvalid, "invalid write-zeroes flags")
		}
		zeroer, ok := s.device.(blockpkg.Zeroer)
		if !ok || !s.device.Capabilities().Zero {
			return s.commandError(wire, request, state, nbdErrNotSup, blockpkg.ErrUnsupported.Error())
		}
		if err := zeroer.ZeroAt(int64(request.offset), length); err != nil {
			return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
		}
		if request.flags&nbdCommandFlagFUA != 0 {
			if err := s.flush(); err != nil {
				return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
			}
		}
		s.zeroes.Add(1)
		return wire.commandDone(request, state)

	case nbdCommandTrim:
		if request.flags & ^nbdCommandFlagFUA != 0 {
			return s.commandError(wire, request, state, nbdErrInvalid, "invalid trim flags")
		}
		trimmer, ok := s.device.(blockpkg.Trimmer)
		if !ok || !s.device.Capabilities().Trim {
			return s.commandError(wire, request, state, nbdErrNotSup, blockpkg.ErrUnsupported.Error())
		}
		if err := trimmer.TrimAt(int64(request.offset), length); err != nil {
			return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
		}
		if request.flags&nbdCommandFlagFUA != 0 {
			if err := s.flush(); err != nil {
				return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
			}
		}
		s.trims.Add(1)
		return wire.commandDone(request, state)

	case nbdCommandBlockStatus:
		if !state.structured || !state.allocation || request.flags & ^nbdCommandFlagReqOne != 0 {
			return s.commandError(wire, request, state, nbdErrNotSup, "allocation metadata is not negotiated")
		}
		extents := []blockpkg.Extent{{Offset: int64(request.offset), Length: length, Allocated: true}}
		if provider, ok := s.device.(blockpkg.Extenter); ok && s.device.Capabilities().Extents {
			var err error
			extents, err = provider.Extents(int64(request.offset), length)
			if err != nil {
				return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
			}
		}
		if request.flags&nbdCommandFlagReqOne != 0 && len(extents) > 1 {
			extents = extents[:1]
		}
		payload := make([]byte, 4+len(extents)*8)
		binary.BigEndian.PutUint32(payload, 1)
		for index, extent := range extents {
			if extent.Length <= 0 || extent.Length > math.MaxUint32 {
				return s.commandError(wire, request, state, nbdErrOverflow, "extent is too large")
			}
			status := uint32(0)
			if !extent.Allocated {
				status = nbdStateHole | nbdStateZero
			}
			binary.BigEndian.PutUint32(payload[4+index*8:], uint32(extent.Length))
			binary.BigEndian.PutUint32(payload[8+index*8:], status)
		}
		return wire.structuredReply(request.cookie, nbdStructuredDone, nbdStructuredBlockStatus, payload)

	case nbdCommandCache:
		if request.flags != 0 {
			return s.commandError(wire, request, state, nbdErrInvalid, "invalid cache flags")
		}
		prefetcher, ok := s.device.(blockpkg.Prefetcher)
		if !ok || !s.device.Capabilities().Prefetch {
			return s.commandError(wire, request, state, nbdErrNotSup, blockpkg.ErrUnsupported.Error())
		}
		if err := prefetcher.Prefetch(int64(request.offset), length); err != nil {
			return s.commandError(wire, request, state, nbdErrorCode(err), err.Error())
		}
		s.cacheHints.Add(1)
		return wire.commandDone(request, state)
	default:
		return s.commandError(wire, request, state, nbdErrNotSup, "unknown command")
	}
}

func (s *NBDServer) aligned(offset uint64, length uint32) bool {
	minimum := uint64(s.device.Geometry().MinimumTransfer)
	return minimum != 0 && offset%minimum == 0 && uint64(length)%minimum == 0
}

func (s *NBDServer) flush() error {
	flusher, ok := s.device.(blockpkg.Flusher)
	if !ok || !s.device.Capabilities().Flush {
		return blockpkg.ErrUnsupported
	}
	return flusher.Flush()
}

func nbdErrorCode(err error) uint32 {
	var capacity *blockstar.BlockCapacityError
	switch {
	case errors.Is(err, blockpkg.ErrReadOnly):
		return nbdErrPerm
	case errors.Is(err, blockpkg.ErrUnsupported):
		return nbdErrNotSup
	case errors.Is(err, blockpkg.ErrOutOfRange):
		return nbdErrInvalid
	case errors.As(err, &capacity):
		return nbdErrNoSpace
	default:
		return nbdErrIO
	}
}

type nbdWire struct {
	reader  *bufio.Reader
	writer  *bufio.Writer
	writeMu sync.Mutex
}

func (w *nbdWire) read(values ...any) error {
	for _, value := range values {
		if err := binary.Read(w.reader, binary.BigEndian, value); err != nil {
			return err
		}
	}
	return nil
}

func (w *nbdWire) writeValues(values ...any) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	for _, value := range values {
		if err := binary.Write(w.writer, binary.BigEndian, value); err != nil {
			return err
		}
	}
	return w.writer.Flush()
}

func (w *nbdWire) writeBytes(data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *nbdWire) optionReply(option, reply uint32, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := binary.Write(w.writer, binary.BigEndian, nbdOptionReplyMagic); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, option); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, reply); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *nbdWire) readRequest(channel channelpkg.ByteChannel, timeout time.Duration) (nbdRequest, error) {
	var magic uint32
	var request nbdRequest
	// An established NBD transmission is allowed to remain idle indefinitely.
	// Arm the request deadline only after the peer starts a new frame; applying
	// it while waiting for the first byte disconnects healthy, idle VM disks and
	// turns the guest's next cache miss into an I/O error.
	setByteChannelReadDeadline(channel, 0)
	var magicBytes [4]byte
	if _, err := io.ReadFull(w.reader, magicBytes[:1]); err != nil {
		return request, err
	}
	setByteChannelReadDeadline(channel, timeout)
	if _, err := io.ReadFull(w.reader, magicBytes[1:]); err != nil {
		return request, err
	}
	magic = binary.BigEndian.Uint32(magicBytes[:])
	if err := w.read(&request.flags, &request.kind, &request.cookie, &request.offset, &request.length); err != nil {
		return request, err
	}
	if magic != nbdRequestMagic {
		return request, fmt.Errorf("nbd: invalid request magic %#x", magic)
	}
	return request, nil
}

func (w *nbdWire) simpleReply(cookie uint64, errno uint32, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := binary.Write(w.writer, binary.BigEndian, nbdSimpleReplyMagic); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, errno); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, cookie); err != nil {
		return err
	}
	if errno == 0 && len(data) != 0 {
		if _, err := w.writer.Write(data); err != nil {
			return err
		}
	}
	return w.writer.Flush()
}

func (w *nbdWire) structuredReply(cookie uint64, flags, replyType uint16, data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := binary.Write(w.writer, binary.BigEndian, nbdStructuredMagic); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, flags); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, replyType); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, cookie); err != nil {
		return err
	}
	if err := binary.Write(w.writer, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *nbdWire) commandDone(request nbdRequest, state nbdNegotiationState) error {
	if state.structured {
		return w.structuredReply(request.cookie, nbdStructuredDone, 0, nil)
	}
	return w.simpleReply(request.cookie, 0, nil)
}

func (w *nbdWire) commandError(request nbdRequest, state nbdNegotiationState, errno uint32, message string) error {
	if state.structured {
		if len(message) > 4096 {
			message = message[:4096]
		}
		payload := make([]byte, 6+len(message))
		binary.BigEndian.PutUint32(payload, errno)
		binary.BigEndian.PutUint16(payload[4:], uint16(len(message)))
		copy(payload[6:], message)
		return w.structuredReply(request.cookie, nbdStructuredDone, nbdStructuredError, payload)
	}
	return w.simpleReply(request.cookie, errno, nil)
}

func (w *nbdWire) discard(length int64) error {
	_, err := io.CopyN(io.Discard, w.reader, length)
	return err
}

func parseNBDInfoRequest(data []byte) (string, []uint16, error) {
	if len(data) < 6 {
		return "", nil, fmt.Errorf("short info request")
	}
	nameLength := int(binary.BigEndian.Uint32(data))
	if nameLength > nbdMaxExportName || nameLength > len(data)-6 {
		return "", nil, fmt.Errorf("invalid export name length")
	}
	name := string(data[4 : 4+nameLength])
	off := 4 + nameLength
	count := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if count > (len(data)-off)/2 || off+count*2 != len(data) {
		return "", nil, fmt.Errorf("invalid info request count")
	}
	requests := make([]uint16, count)
	for index := range requests {
		requests[index] = binary.BigEndian.Uint16(data[off+index*2:])
	}
	return name, requests, nil
}

func parseNBDMetaContextRequest(data []byte) ([]string, string, error) {
	if len(data) < 8 {
		return nil, "", fmt.Errorf("short metadata request")
	}
	nameLength := int(binary.BigEndian.Uint32(data))
	if nameLength > nbdMaxExportName || nameLength > len(data)-8 {
		return nil, "", fmt.Errorf("invalid metadata export name")
	}
	name := string(data[4 : 4+nameLength])
	off := 4 + nameLength
	count := int(binary.BigEndian.Uint32(data[off:]))
	off += 4
	if count > 1024 {
		return nil, "", fmt.Errorf("too many metadata queries")
	}
	queries := make([]string, 0, count)
	for range count {
		if off > len(data)-4 {
			return nil, "", fmt.Errorf("short metadata query")
		}
		length := int(binary.BigEndian.Uint32(data[off:]))
		off += 4
		if length > len(data)-off {
			return nil, "", fmt.Errorf("invalid metadata query length")
		}
		queries = append(queries, string(data[off:off+length]))
		off += length
	}
	if off != len(data) {
		return nil, "", fmt.Errorf("trailing metadata request data")
	}
	return queries, name, nil
}

func setByteChannelDeadline(channel channelpkg.ByteChannel, timeout time.Duration) {
	setter, ok := channel.(channelpkg.DeadlineSetter)
	if !ok {
		return
	}
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	_ = setter.SetDeadline(deadline)
}

func setByteChannelReadDeadline(channel channelpkg.ByteChannel, timeout time.Duration) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if setter, ok := channel.(channelpkg.ReadDeadlineSetter); ok {
		_ = setter.SetReadDeadline(deadline)
		return
	}
	if setter, ok := channel.(channelpkg.DeadlineSetter); ok {
		_ = setter.SetDeadline(deadline)
	}
}
