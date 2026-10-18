package smb

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// session is intentionally transport-independent. Its caller owns the byte
// stream and its lifetime; nothing here binds a host socket or dials a host.
// A connection has exactly one session and a bounded sequence window.
type session struct {
	files         FileSystem
	share         string
	tree          uint32
	handles       map[[16]byte]*openFile
	related       [16]byte
	trace         func(uint16, uint32)
	traceCreate   func(CreateTrace)
	auth          ntlmServer
	guid          [16]byte
	started       time.Time
	negotiated    bool
	multiProtocol bool
	id            uint64
	key           []byte
	credits       map[uint64]bool
	nextCredit    uint64
	closing       bool
}

func newSession(user, domain, password string, guid [16]byte, started time.Time) (*session, error) {
	if user == "" || password == "" || len(utf16Bytes(user)) > 512 || len(utf16Bytes(domain)) > 512 {
		return nil, errors.New("SMB requires a bounded user and nonempty password")
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	sid := le.Uint64(id[:])
	if sid == 0 || sid == math.MaxUint64 {
		sid = 1
	}
	return &session{auth: ntlmServer{user: user, domain: domain, password: password}, guid: guid, started: started, id: sid, credits: map[uint64]bool{0: true}, nextCredit: 1}, nil
}

func (s *session) serve(stream io.ReadWriteCloser) error {
	defer stream.Close()
	defer s.closeFiles()
	defer func() { clear(s.key); s.auth = ntlmServer{} }()
	for {
		if timed, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
			// Authenticated desktop connections may be idle indefinitely.
			// Server.Close still interrupts them; the connection cap bounds resources.
			var deadline time.Time
			if len(s.key) == 0 {
				deadline = time.Now().Add(30 * time.Second)
			}
			_ = timed.SetDeadline(deadline)
		}
		frame, err := readFrame(stream)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		reply, err := s.process(frame)
		if err != nil {
			return err
		}
		if len(reply) != 0 {
			if err := writeFrame(stream, reply); err != nil {
				return err
			}
		}
		if s.closing {
			return nil
		}
	}
}

func (s *session) process(frame []byte) ([]byte, error) {
	if s.closing {
		return nil, errProtocol
	}
	if len(frame) >= 4 && string(frame[:4]) == "\xffSMB" {
		return s.multiNegotiate(frame)
	}
	requests, err := parseRequests(frame)
	if err != nil {
		return nil, fmt.Errorf("%w: header=%x", err, frame[:min(64, len(frame))])
	}
	// Validate the entire chain before invoking any command. A bad signature
	// on a later command must not permit effects from an earlier command.
	used := make(map[uint64]bool, len(requests))
	for _, req := range requests {
		if len(s.key) != 0 {
			if req.flags&flagSigned == 0 || !validSignature(s.key, req.raw) {
				return nil, errAuthentication
			}
		} else if req.flags&flagSigned != 0 {
			return nil, errAuthentication
		}
		if req.command == 12 {
			continue
		} // CANCEL reuses an outstanding message ID.
		if !s.credits[req.message] || used[req.message] {
			return nil, fmt.Errorf("%w: command=%d ungranted message=%d", errProtocol, req.command, req.message)
		}
		used[req.message] = true
	}
	for id := range used {
		delete(s.credits, id)
	}
	s.related = [16]byte{}
	var replies [][]byte
	for _, req := range requests {
		if req.flags&flagRelated != 0 {
			prev := replies[len(replies)-1]
			req.session, req.tree = le.Uint64(prev[40:]), le.Uint32(prev[36:])
		}
		if req.command == 12 {
			// All current operations complete synchronously; no outstanding request
			// can be canceled. CANCEL has no response and consumes no credit.
			if !structure(req, 4, 4) || len(s.key) == 0 || req.session != s.id {
				return nil, errProtocol
			}
			continue
		}
		if req.flags&flagRelated == 0 {
			s.related = [16]byte{}
		}
		body, status := s.dispatch(&req)
		if s.trace != nil {
			s.trace(req.command, status)
		}
		if body == nil {
			body = errorBody()
		}
		reply := response(req, status, body)
		grant := int(req.credits)
		if grant < 1 {
			grant = 1
		}
		if grant > 128-len(s.credits) {
			grant = 128 - len(s.credits)
		}
		for range grant {
			if s.nextCredit == math.MaxUint64 {
				return nil, errProtocol
			}
			s.credits[s.nextCredit] = true
			s.nextCredit++
		}
		le.PutUint16(reply[14:], uint16(grant))
		replies = append(replies, reply)
	}
	var out []byte
	for i, reply := range replies {
		if i+1 < len(replies) {
			reply = append(reply, make([]byte, (8-len(reply)%8)%8)...)
			le.PutUint32(reply[20:], uint32(len(reply)))
		}
		if len(s.key) != 0 {
			sign(s.key, reply)
		}
		out = append(out, reply...)
	}
	return out, nil
}

func (s *session) dispatch(req *request) ([]byte, uint32) {
	if req.command == 0 {
		return s.negotiate(req)
	}
	if !s.negotiated {
		return nil, statusInvalidParameter
	}
	if req.command == 1 {
		return s.setup(req)
	}
	if len(s.key) == 0 || req.session != s.id {
		return nil, statusUserSessionDeleted
	}
	switch req.command {
	case 2: // LOGOFF; sign the last reply before forgetting the session key.
		if !structure(*req, 4, 4) {
			return nil, statusInvalidParameter
		}
		s.closing = true
		return []byte{4, 0, 0, 0}, statusSuccess
	case 13: // ECHO
		if !structure(*req, 4, 4) {
			return nil, statusInvalidParameter
		}
		return []byte{4, 0, 0, 0}, statusSuccess
	case 3:
		return s.treeConnect(req)
	default:
		return s.fileCommand(req)
	}
}
func (s *session) negotiate(req *request) ([]byte, uint32) {
	if s.negotiated || req.session != 0 || req.tree != 0 || !structure(*req, 36, 36) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	count := int(le.Uint16(b[2:]))
	if count == 0 || count > 64 || count > (len(b)-36)/2 {
		return nil, statusInvalidParameter
	}
	if le.Uint16(b[4:])&3 == 0 {
		return nil, statusNotSupported
	}
	supported := false
	for i := 0; i < count; i++ {
		if le.Uint16(b[36+2*i:]) == 0x210 {
			supported = true
		}
	}
	if !supported {
		s.closing = true
		return nil, statusNotSupported
	}
	s.negotiated = true
	token := spnegoOffer()
	out := make([]byte, 64)
	le.PutUint16(out, 65)
	le.PutUint16(out[2:], 3) // Signing enabled AND required.
	le.PutUint16(out[4:], 0x210)
	copy(out[8:], s.guid[:])
	// No DFS, leasing, multichannel, persistent handles, or large-MTU claim.
	le.PutUint32(out[28:], maxIO)
	le.PutUint32(out[32:], maxIO)
	le.PutUint32(out[36:], maxIO)
	le.PutUint64(out[40:], windowsTime(time.Now()))
	le.PutUint64(out[48:], windowsTime(s.started))
	le.PutUint16(out[56:], 128)
	le.PutUint16(out[58:], uint16(len(token)))
	return append(out, token...), statusSuccess
}
func (s *session) setup(req *request) ([]byte, uint32) {
	if len(s.key) != 0 || !structure(*req, 25, 24) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	if b[2] != 0 || b[3]&3 == 0 || req.tree != 0 {
		return nil, statusInvalidParameter
	}
	token, ok := field(req.raw, uint32(le.Uint16(b[12:])), uint32(le.Uint16(b[14:])), 88)
	if !ok || len(token) == 0 {
		return nil, statusInvalidParameter
	}
	var reply []byte
	var err error
	status := statusMoreProcessing
	if s.auth.challenge == nil {
		if req.session != 0 {
			return nil, statusUserSessionDeleted
		}
		reply, err = s.auth.start(token)
	} else {
		if req.session != s.id {
			return nil, statusUserSessionDeleted
		}
		s.key, err = s.auth.finish(token)
		if err == nil {
			reply, status = spnegoReply(nil, true), statusSuccess
		}
	}
	req.session = s.id
	if err != nil {
		s.closing = true
		return nil, statusLogonFailure
	}
	out := make([]byte, 8)
	le.PutUint16(out, 9)
	// SessionFlags = 0: never mark this authenticated session guest or null.
	le.PutUint16(out[4:], 72)
	le.PutUint16(out[6:], uint16(len(reply)))
	return append(out, reply...), status
}
