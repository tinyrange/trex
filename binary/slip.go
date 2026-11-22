package binary

import "fmt"

// SLIPEncode frames one RFC1055 packet, including a leading END to discard
// preceding line noise. The empty packet encodes as two ENDs and is ignored
// by receivers. maximum bounds the unescaped packet length.
func SLIPEncode(packet []byte, maximum int) ([]byte, error) {
	if maximum < 1 || maximum > 1<<20 || len(packet) > maximum {
		return nil, fmt.Errorf("slip: packet exceeds limit or invalid maximum")
	}
	out := make([]byte, 0, len(packet)+2)
	out = append(out, 0xc0)
	for _, b := range packet {
		switch b {
		case 0xc0:
			out = append(out, 0xdb, 0xdc)
		case 0xdb:
			out = append(out, 0xdb, 0xdd)
		default:
			out = append(out, b)
		}
	}
	return append(out, 0xc0), nil
}

// SLIPDecode decodes complete RFC1055 packets from a bounded stream chunk.
// Empty frames are ignored. remainder is the unmodified partial wire packet;
// prepend it to the next chunk (including a partial escape). maximum bounds
// each decoded packet. Malformed escapes and oversized packets are errors;
// no packets are returned on error. Returned storage is independent of data.
func SLIPDecode(data []byte, maximum int) (packets [][]byte, remainder []byte, err error) {
	if maximum < 1 || maximum > 1<<20 || len(data) > 16<<20 {
		return nil, nil, fmt.Errorf("slip: invalid maximum or stream chunk exceeds16MiB")
	}
	var packet []byte
	escaped, start := false, 0
	for i, b := range data {
		if b == 0xc0 {
			if escaped {
				return nil, nil, fmt.Errorf("slip: unfinished escape at byte%d", i)
			}
			if len(packet) != 0 {
				packets = append(packets, packet)
				packet = nil
			}
			start = i + 1
			continue
		}
		if escaped {
			switch b {
			case 0xdc:
				b = 0xc0
			case 0xdd:
				b = 0xdb
			default:
				return nil, nil, fmt.Errorf("slip: invalid escape at byte%d", i)
			}
			escaped = false
		} else if b == 0xdb {
			escaped = true
			continue
		}
		if len(packet) == maximum {
			return nil, nil, fmt.Errorf("slip: packet exceeds%d bytes", maximum)
		}
		packet = append(packet, b)
	}
	return packets, append([]byte(nil), data[start:]...), nil
}
