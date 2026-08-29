package nbd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	blockpkg "github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	channelpkg "github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
)

func testBlockDevice(t *testing.T, size int) *blockpkg.FileDevice {
	t.Helper()
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(index * 31)
	}
	device, err := blockpkg.NewFileDevice(&starfile.Bytes{Name: "block-test", Data: data}, blockpkg.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

type testNBDOptionReply struct {
	option uint32
	kind   uint32
	data   []byte
}

type testNBDStructuredReply struct {
	flags  uint16
	kind   uint16
	cookie uint64
	data   []byte
}

type blockingNBDDevice struct {
	mu      sync.RWMutex
	data    []byte
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (d *blockingNBDDevice) ReadAt(data []byte, offset int64) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	copy(data, d.data[offset:offset+int64(len(data))])
	return len(data), nil
}

func (d *blockingNBDDevice) WriteAt(data []byte, offset int64) (int, error) {
	d.once.Do(func() { close(d.started) })
	<-d.release
	d.mu.Lock()
	defer d.mu.Unlock()
	copy(d.data[offset:], data)
	return len(data), nil
}

func (d *blockingNBDDevice) Geometry() blockpkg.Geometry {
	return blockpkg.Geometry{Size: int64(len(d.data)), LogicalBlockSize: 512, PhysicalBlockSize: 512, MinimumTransfer: 512, PreferredTransfer: 4096, MaximumTransfer: 4096}
}

func (d *blockingNBDDevice) Capabilities() blockpkg.Capabilities {
	return blockpkg.Capabilities{Writable: true, Concurrent: true}
}

func TestNBDServerStructuredReadWriteAndAllocation(t *testing.T) {
	base := testBlockDevice(t, 4096)
	overlay, err := blockstar.NewOverlayDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewNBDServer(overlay, "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	metrics := &lifecycle.Metrics{}
	server.metrics = metrics
	server.handshakeTimeout = time.Second
	server.requestTimeout = time.Second

	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(context.Background(), serverConn) }()
	defer clientConn.Close()

	var magic, options uint64
	var handshakeFlags uint16
	readNBDValues(t, clientConn, &magic, &options, &handshakeFlags)
	if magic != nbdMagic || options != nbdOptionsMagic || handshakeFlags&nbdFlagFixedNewstyle == 0 {
		t.Fatalf("handshake = %#x %#x %#x", magic, options, handshakeFlags)
	}
	writeNBDValues(t, clientConn, nbdClientFixedNewstyle|nbdClientNoZeroes)

	sendNBDOption(t, clientConn, nbdOptStructuredReply, nil)
	reply := readNBDOptionReply(t, clientConn)
	if reply.option != nbdOptStructuredReply || reply.kind != nbdRepACK {
		t.Fatalf("structured option reply = %#v", reply)
	}

	meta := nbdMetaContextPayload("disk", "base:allocation")
	sendNBDOption(t, clientConn, nbdOptSetMetaContext, meta)
	reply = readNBDOptionReply(t, clientConn)
	if reply.kind != nbdRepMetaContext || len(reply.data) < 4 || binary.BigEndian.Uint32(reply.data) != 1 {
		t.Fatalf("metadata reply = %#v", reply)
	}
	if reply = readNBDOptionReply(t, clientConn); reply.kind != nbdRepACK {
		t.Fatalf("metadata ack = %#v", reply)
	}

	goPayload := nbdInfoPayload("disk", nbdInfoBlockSize)
	sendNBDOption(t, clientConn, nbdOptGo, goPayload)
	seenExport, seenBlock, seenFastZero := false, false, false
	for {
		reply = readNBDOptionReply(t, clientConn)
		if reply.kind == nbdRepACK {
			break
		}
		if reply.kind != nbdRepInfo || len(reply.data) < 2 {
			t.Fatalf("go reply = %#v", reply)
		}
		switch binary.BigEndian.Uint16(reply.data) {
		case nbdInfoExport:
			seenExport = true
			seenFastZero = len(reply.data) >= 12 && binary.BigEndian.Uint16(reply.data[10:12])&nbdTransmissionSendFastZero != 0
		case nbdInfoBlockSize:
			seenBlock = true
		}
	}
	if !seenExport || !seenBlock || !seenFastZero {
		t.Fatalf("GO info export=%v block=%v fast-zero=%v", seenExport, seenBlock, seenFastZero)
	}

	if _, err := overlay.Commit(); err == nil {
		t.Fatal("overlay commit succeeded while NBD lease was active")
	}

	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandRead, cookie: 1, offset: 0, length: 512}, nil)
	structured := readNBDStructuredReply(t, clientConn)
	if structured.cookie != 1 || structured.kind != nbdStructuredOffsetData || structured.flags&nbdStructuredDone == 0 {
		t.Fatalf("read reply = %#v", structured)
	}
	if len(structured.data) != 520 || binary.BigEndian.Uint64(structured.data) != 0 {
		t.Fatalf("read payload size/offset = %d/%d", len(structured.data), binary.BigEndian.Uint64(structured.data))
	}
	wantRead := make([]byte, 512)
	if _, err := base.ReadAt(wantRead, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(structured.data[8:], wantRead) {
		t.Fatal("NBD read differs from base")
	}

	writeData := bytes.Repeat([]byte{0xa5}, 512)
	sendNBDRequest(t, clientConn, nbdRequest{flags: nbdCommandFlagFUA, kind: nbdCommandWrite, cookie: 2, offset: 512, length: 512}, writeData)
	structured = readNBDStructuredReply(t, clientConn)
	if structured.cookie != 2 || structured.kind != 0 || structured.flags&nbdStructuredDone == 0 {
		t.Fatalf("write reply = %#v", structured)
	}

	sendNBDRequest(t, clientConn, nbdRequest{flags: nbdCommandFlagFastZero, kind: nbdCommandWriteZeroes, cookie: 3, offset: 512, length: 512}, nil)
	structured = readNBDStructuredReply(t, clientConn)
	if structured.cookie != 3 || structured.kind != 0 || structured.flags&nbdStructuredDone == 0 {
		t.Fatalf("fast-zero reply = %#v", structured)
	}
	zeroed := make([]byte, 512)
	if _, err := overlay.ReadAt(zeroed, 512); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(zeroed, make([]byte, 512)) {
		t.Fatal("fast-zero request did not clear overlay data")
	}

	sendNBDRequest(t, clientConn, nbdRequest{flags: nbdCommandFlagReqOne, kind: nbdCommandBlockStatus, cookie: 4, offset: 0, length: 512}, nil)
	structured = readNBDStructuredReply(t, clientConn)
	if structured.kind != nbdStructuredBlockStatus || len(structured.data) != 12 {
		t.Fatalf("block status reply = %#v", structured)
	}
	if binary.BigEndian.Uint32(structured.data) != 1 || binary.BigEndian.Uint32(structured.data[4:]) != 512 {
		t.Fatalf("block status payload = %x", structured.data)
	}

	sendNBDRequest(t, clientConn, nbdRequest{flags: nbdCommandFlagReqOne, kind: nbdCommandWriteZeroes, cookie: 5, offset: 512, length: 512}, nil)
	structured = readNBDStructuredReply(t, clientConn)
	if structured.cookie != 5 || structured.kind != nbdStructuredError || structured.flags&nbdStructuredDone == 0 {
		t.Fatalf("invalid request reply = %#v", structured)
	}

	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandDisconnect, cookie: 6}, nil)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}

	baseData := make([]byte, 512)
	if _, err := base.ReadAt(baseData, 512); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(baseData, writeData) {
		t.Fatal("NBD write modified overlay base")
	}
	overlayData := make([]byte, 512)
	if _, err := overlay.ReadAt(overlayData, 512); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(overlayData, make([]byte, 512)) {
		t.Fatal("NBD fast-zero missing from overlay")
	}
	stats := server.Stats()
	if got := stats.CommandErrors; got != 1 {
		t.Fatalf("command_errors = %d", got)
	}
	if metrics.NBDReadBytes.Load() != 512 || metrics.NBDWriteBytes.Load() != 512 {
		t.Fatalf("runtime NBD bytes read=%d write=%d", metrics.NBDReadBytes.Load(), metrics.NBDWriteBytes.Load())
	}
	if got := stats.LastError; !strings.Contains(got, "invalid write-zeroes flags") {
		t.Fatalf("last_error = %q", got)
	}
	if _, err := overlay.Commit(); err != nil {
		t.Fatalf("commit after disconnect: %v", err)
	}
}

func TestNBDServerRejectsUnsupportedStructuredRepliesCleanly(t *testing.T) {
	server, err := NewNBDServer(testBlockDevice(t, 4096), "", 4096)
	if err != nil {
		t.Fatal(err)
	}
	server.structured = false
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(context.Background(), serverConn) }()
	defer clientConn.Close()

	var magic, options uint64
	var flags uint16
	readNBDValues(t, clientConn, &magic, &options, &flags)
	writeNBDValues(t, clientConn, nbdClientFixedNewstyle|nbdClientNoZeroes)
	sendNBDOption(t, clientConn, nbdOptStructuredReply, nil)
	if reply := readNBDOptionReply(t, clientConn); reply.kind != nbdRepErrUnsup {
		t.Fatalf("structured rejection = %#v", reply)
	}
	sendNBDOption(t, clientConn, nbdOptGo, nbdInfoPayload(""))
	for {
		if reply := readNBDOptionReply(t, clientConn); reply.kind == nbdRepACK {
			break
		}
	}
	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandRead, cookie: 7, offset: 0, length: 512}, nil)
	var replyMagic, errno uint32
	var cookie uint64
	readNBDValues(t, clientConn, &replyMagic, &errno, &cookie)
	if replyMagic != nbdSimpleReplyMagic || errno != 0 || cookie != 7 {
		t.Fatalf("simple reply header = %#x %d %d", replyMagic, errno, cookie)
	}
	data := make([]byte, 512)
	if _, err := io.ReadFull(clientConn, data); err != nil {
		t.Fatal(err)
	}
	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandDisconnect}, nil)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestNBDServerRoutesAdvertisedCacheHints(t *testing.T) {
	cache, err := blockstar.NewCachedDevice(testBlockDevice(t, 4096), 4096, 512)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewNBDServer(cache, "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(context.Background(), serverConn) }()
	defer clientConn.Close()
	var magic, options uint64
	var flags uint16
	readNBDValues(t, clientConn, &magic, &options, &flags)
	writeNBDValues(t, clientConn, nbdClientFixedNewstyle|nbdClientNoZeroes)
	sendNBDOption(t, clientConn, nbdOptStructuredReply, nil)
	if reply := readNBDOptionReply(t, clientConn); reply.kind != nbdRepACK {
		t.Fatalf("structured reply = %#v", reply)
	}
	sendNBDOption(t, clientConn, nbdOptGo, nbdInfoPayload("disk"))
	advertised := false
	for {
		reply := readNBDOptionReply(t, clientConn)
		if reply.kind == nbdRepACK {
			break
		}
		if reply.kind == nbdRepInfo && len(reply.data) == 12 && binary.BigEndian.Uint16(reply.data[10:])&nbdTransmissionSendCache != 0 {
			advertised = true
		}
	}
	if !advertised {
		t.Fatal("NBD export omitted cache capability")
	}
	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandCache, cookie: 9, offset: 0, length: 512}, nil)
	if reply := readNBDStructuredReply(t, clientConn); reply.cookie != 9 || reply.kind != 0 {
		t.Fatalf("cache reply = %#v", reply)
	}
	if server.cacheHints.Load() != 1 || cache.Misses() == 0 {
		t.Fatalf("cache hint stats hints=%d misses=%d", server.cacheHints.Load(), cache.Misses())
	}
	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandDisconnect}, nil)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestNBDRequestParsersRejectMalformedLengths(t *testing.T) {
	if _, _, err := parseNBDInfoRequest([]byte{0, 0, 0, 8, 0, 0}); err == nil {
		t.Fatal("malformed info request accepted")
	}
	if _, _, err := parseNBDMetaContextRequest([]byte{0, 0, 0, 0, 0, 0, 0, 1}); err == nil {
		t.Fatal("malformed metadata request accepted")
	}
}

func TestNBDServerCancellationInterruptsNegotiation(t *testing.T) {
	server, err := NewNBDServer(testBlockDevice(t, 4096), "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, serverConn) }()
	var magic, options uint64
	var flags uint16
	readNBDValues(t, clientConn, &magic, &options, &flags)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled negotiation returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled NBD negotiation did not stop")
	}
}

func TestNBDReadCannotOvertakeBlockedWrite(t *testing.T) {
	device := &blockingNBDDevice{data: make([]byte, 4096), started: make(chan struct{}), release: make(chan struct{})}
	server, err := NewNBDServer(device, "disk", 4096)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(context.Background(), serverConn) }()
	defer clientConn.Close()

	var magic, options uint64
	var flags uint16
	readNBDValues(t, clientConn, &magic, &options, &flags)
	writeNBDValues(t, clientConn, nbdClientFixedNewstyle|nbdClientNoZeroes)
	sendNBDOption(t, clientConn, nbdOptStructuredReply, nil)
	if reply := readNBDOptionReply(t, clientConn); reply.kind != nbdRepACK {
		t.Fatalf("structured reply = %#v", reply)
	}
	sendNBDOption(t, clientConn, nbdOptGo, nbdInfoPayload("disk"))
	for {
		if reply := readNBDOptionReply(t, clientConn); reply.kind == nbdRepACK {
			break
		}
	}

	written := bytes.Repeat([]byte{0x5a}, 512)
	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandWrite, cookie: 1, offset: 0, length: 512}, written)
	select {
	case <-device.started:
	case <-time.After(time.Second):
		t.Fatal("write did not reach block device")
	}
	readSent := make(chan error, 1)
	go func() {
		packet := make([]byte, 28)
		binary.BigEndian.PutUint32(packet[0:4], nbdRequestMagic)
		binary.BigEndian.PutUint16(packet[6:8], nbdCommandRead)
		binary.BigEndian.PutUint64(packet[8:16], 2)
		binary.BigEndian.PutUint32(packet[24:28], 512)
		readSent <- channelpkg.WriteAll(clientConn, packet)
	}()
	if err := clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	probe := make([]byte, 1)
	if _, err := clientConn.Read(probe); err == nil {
		t.Fatal("server replied to a later read while the preceding write was blocked")
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(device.release)
	writeReply := readNBDStructuredReply(t, clientConn)
	if err := <-readSent; err != nil {
		t.Fatal(err)
	}
	readReply := readNBDStructuredReply(t, clientConn)
	if writeReply.cookie != 1 || readReply.cookie != 2 || !bytes.Equal(readReply.data[8:], written) {
		t.Fatalf("ordered replies write=%#v read=%#v", writeReply, readReply)
	}
	sendNBDRequest(t, clientConn, nbdRequest{kind: nbdCommandDisconnect}, nil)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func nbdInfoPayload(name string, requests ...uint16) []byte {
	data := make([]byte, 6+len(name)+len(requests)*2)
	binary.BigEndian.PutUint32(data, uint32(len(name)))
	copy(data[4:], name)
	off := 4 + len(name)
	binary.BigEndian.PutUint16(data[off:], uint16(len(requests)))
	off += 2
	for _, request := range requests {
		binary.BigEndian.PutUint16(data[off:], request)
		off += 2
	}
	return data
}

func nbdMetaContextPayload(name string, queries ...string) []byte {
	length := 8 + len(name)
	for _, query := range queries {
		length += 4 + len(query)
	}
	data := make([]byte, length)
	binary.BigEndian.PutUint32(data, uint32(len(name)))
	copy(data[4:], name)
	off := 4 + len(name)
	binary.BigEndian.PutUint32(data[off:], uint32(len(queries)))
	off += 4
	for _, query := range queries {
		binary.BigEndian.PutUint32(data[off:], uint32(len(query)))
		off += 4
		copy(data[off:], query)
		off += len(query)
	}
	return data
}

func sendNBDOption(t *testing.T, writer io.Writer, option uint32, data []byte) {
	t.Helper()
	writeNBDValues(t, writer, nbdOptionsMagic, option, uint32(len(data)))
	if len(data) != 0 {
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}

func readNBDOptionReply(t *testing.T, reader io.Reader) testNBDOptionReply {
	t.Helper()
	var magic uint64
	var reply testNBDOptionReply
	var length uint32
	readNBDValues(t, reader, &magic, &reply.option, &reply.kind, &length)
	if magic != nbdOptionReplyMagic {
		t.Fatalf("option reply magic = %#x", magic)
	}
	if length > nbdMaxOptionSize {
		t.Fatalf("option reply length = %d", length)
	}
	reply.data = make([]byte, length)
	if _, err := io.ReadFull(reader, reply.data); err != nil {
		t.Fatal(err)
	}
	return reply
}

func sendNBDRequest(t *testing.T, writer io.Writer, request nbdRequest, data []byte) {
	t.Helper()
	writeNBDValues(t, writer, nbdRequestMagic, request.flags, request.kind, request.cookie, request.offset, request.length)
	if len(data) != 0 {
		if uint32(len(data)) != request.length {
			t.Fatalf("request payload length %d, header %d", len(data), request.length)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}

func readNBDStructuredReply(t *testing.T, reader io.Reader) testNBDStructuredReply {
	t.Helper()
	var magic uint32
	var reply testNBDStructuredReply
	var length uint32
	readNBDValues(t, reader, &magic, &reply.flags, &reply.kind, &reply.cookie, &length)
	if magic != nbdStructuredMagic {
		t.Fatalf("structured reply magic = %#x", magic)
	}
	if length > nbdDefaultMaxRequest+4096 {
		t.Fatalf("structured reply length = %d", length)
	}
	reply.data = make([]byte, length)
	if _, err := io.ReadFull(reader, reply.data); err != nil {
		t.Fatal(err)
	}
	return reply
}

func readNBDValues(t *testing.T, reader io.Reader, values ...any) {
	t.Helper()
	for _, value := range values {
		if err := binary.Read(reader, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
}

func writeNBDValues(t *testing.T, writer io.Writer, values ...any) {
	t.Helper()
	for _, value := range values {
		if err := binary.Write(writer, binary.BigEndian, value); err != nil {
			t.Fatal(fmt.Errorf("write NBD value: %w", err))
		}
	}
}
