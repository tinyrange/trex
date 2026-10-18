package smb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// These bounds apply before allocating a frame or walking a compound chain.
// SMB 2.1 large MTU is not advertised: each command uses one credit and at
// most 64 KiB of file data. Encryption and SMB1 are intentionally unsupported.
const maxFrame = 2 << 20
const maxCompound = 16
const maxIO = 65536
const headerSize = 64
const flagResponse = 1
const flagAsync = 2
const flagRelated = 4
const flagSigned = 8

var errProtocol = errors.New("invalid SMB2 message")
var le = binary.LittleEndian

const (
	statusSuccess            uint32 = 0
	statusMoreProcessing     uint32 = 0xc0000016
	statusInvalidParameter   uint32 = 0xc000000d
	statusAccessDenied       uint32 = 0xc0000022
	statusLogonFailure       uint32 = 0xc000006d
	statusNotSupported       uint32 = 0xc00000bb
	statusUserSessionDeleted uint32 = 0xc0000203
	statusBadNetworkName     uint32 = 0xc00000cc
)

// readFrame implements direct TCP transport, not NetBIOS session service.
func readFrame(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	if prefix[0] != 0 || n < headerSize || n > maxFrame {
		return nil, errProtocol
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func writeFrame(w io.Writer, b []byte) error {
	if len(b) < headerSize || len(b) > maxFrame {
		return errProtocol
	}
	prefix := [4]byte{0, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	if err := writeAll(w, prefix[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}

type request struct {
	raw     []byte
	command uint16
	credits uint16
	flags   uint32
	message uint64
	session uint64
	tree    uint32
}

func parseRequests(frame []byte) ([]request, error) {
	if len(frame) > maxFrame {
		return nil, errProtocol
	}
	var requests []request
	for {
		if len(frame) < headerSize || string(frame[:4]) != "\xfeSMB" || le.Uint16(frame[4:]) != headerSize {
			return nil, errProtocol
		}
		flags := le.Uint32(frame[16:])
		// This server supports only synchronous requests, with no DFS or replay.
		if flags & ^uint32(flagRelated|flagSigned) != 0 || le.Uint16(frame[6:]) > 1 || le.Uint32(frame[8:]) != 0 {
			return nil, errProtocol
		}
		next := int(le.Uint32(frame[20:]))
		size := len(frame)
		if next != 0 {
			if next < headerSize || next%8 != 0 || next > len(frame)-headerSize {
				return nil, errProtocol
			}
			size = next
		}
		req := request{raw: frame[:size], command: le.Uint16(frame[12:]), credits: le.Uint16(frame[14:]), flags: flags, message: le.Uint64(frame[24:]), tree: le.Uint32(frame[36:]), session: le.Uint64(frame[40:])}
		if len(requests) == 0 && flags&flagRelated != 0 {
			return nil, errProtocol
		}
		requests = append(requests, req)
		if len(requests) > maxCompound {
			return nil, errProtocol
		}
		if next == 0 {
			break
		}
		frame = frame[next:]
	}
	// Establishment and termination never share a compound with file effects.
	if len(requests) > 1 {
		for _, req := range requests {
			if req.command <= 2 || req.command == 12 {
				return nil, errProtocol
			}
		}
	}
	return requests, nil
}
func signature(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg[:48])
	h.Write(make([]byte, 16))
	h.Write(msg[64:])
	return h.Sum(nil)[:16]
}
func validSignature(key, msg []byte) bool {
	return len(msg) >= headerSize && len(key) == 16 && hmac.Equal(signature(key, msg), msg[48:64])
}
func sign(key, msg []byte) {
	le.PutUint32(msg[16:], le.Uint32(msg[16:])|flagSigned)
	copy(msg[48:64], signature(key, msg))
}
func response(req request, status uint32, body []byte) []byte {
	b := make([]byte, headerSize, headerSize+len(body))
	copy(b, "\xfeSMB")
	le.PutUint16(b[4:], headerSize)
	le.PutUint32(b[8:], status)
	le.PutUint16(b[12:], req.command)
	le.PutUint32(b[16:], flagResponse|(req.flags&flagRelated))
	le.PutUint64(b[24:], req.message)
	copy(b[32:36], req.raw[32:36])
	le.PutUint32(b[36:], req.tree)
	le.PutUint64(b[40:], req.session)
	return append(b, body...)
}
func errorBody() []byte { return []byte{9, 0, 0, 0, 0, 0, 0, 0, 0} }

// field validates an absolute offset within one compound command, not the
// outer transport frame. min prevents a payload from aliasing fixed fields.
func field(msg []byte, offset, length uint32, min int) ([]byte, bool) {
	if uint64(offset) < uint64(min) || uint64(offset) > uint64(len(msg)) || uint64(length) > uint64(len(msg))-uint64(offset) {
		return nil, false
	}
	return msg[int(offset) : int(offset)+int(length)], true
}
func structure(req request, size uint16, fixed int) bool {
	return len(req.raw) >= headerSize+fixed && le.Uint16(req.raw[headerSize:]) == size
}
