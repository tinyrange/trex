package smb

import "bytes"

// multiNegotiate accepts only the legacy-format dialect discovery envelope.
// It never accepts SMB1 authentication, trees, or file commands. The wildcard
// response requires a second, real SMB2 negotiation before session setup.
func (s *session) multiNegotiate(frame []byte) ([]byte, error) {
	if s.multiProtocol || s.negotiated || len(frame) < 35 || frame[4] != 0x72 || frame[32] != 0 || int(le.Uint16(frame[33:])) != len(frame)-35 {
		return nil, errProtocol
	}
	dialects := frame[35:]
	supported := false
	for count := 0; len(dialects) > 0; count++ {
		if count >= 64 || dialects[0] != 2 {
			return nil, errProtocol
		}
		end := bytes.IndexByte(dialects[1:], 0)
		if end < 0 {
			return nil, errProtocol
		}
		if string(dialects[1:1+end]) == "SMB 2.???" {
			supported = true
		}
		dialects = dialects[2+end:]
	}
	if !supported {
		return nil, errProtocol
	}
	request := make([]byte, 102)
	copy(request, []byte{254, 'S', 'M', 'B'})
	le.PutUint16(request[4:], 64)
	le.PutUint16(request[14:], 1)
	le.PutUint16(request[64:], 36)
	le.PutUint16(request[66:], 1)
	le.PutUint16(request[68:], 1)
	le.PutUint16(request[100:], 0x210)
	reply, e := s.process(request)
	if e != nil {
		return nil, e
	}
	le.PutUint16(reply[68:], 0x2ff)
	s.negotiated = false
	s.multiProtocol = true
	return reply, nil
}
