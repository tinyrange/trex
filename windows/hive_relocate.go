package windows

import "strings"

// A drive designator starts a path token, not the tail of an identifier such
// as MMC's FX:{guid} or the ms-appx: URI scheme. Include path separators for
// embedded NT paths and delimiters used by commands, lists and icon resources.
func driveBoundary(c byte) bool {
	return strings.IndexByte("\x00 \t\r\n\\/\"'@=;,(<[", c) >= 0
}

func relocateDriveText(s string, source, target byte) string {
	var out []byte
	for i := 0; i+1 < len(s); i++ {
		if s[i+1] != ':' || (s[i] != source && s[i] != source+32) || (i > 0 && !driveBoundary(s[i-1])) {
			continue
		}
		if out == nil {
			out = []byte(s)
		}
		out[i] = target
		if s[i] == source+32 {
			out[i] += 32
		}
	}
	if out == nil {
		return s
	}
	return string(out)
}

// Work on aligned code units without decoding: REG_SZ/MULTI_SZ can contain
// unpaired surrogates, extra terminators or an odd trailing byte to preserve.
func relocateDriveUTF16(data []byte, source, target byte) []byte {
	var out []byte
	for i := 0; i+3 < len(data); i += 2 {
		if data[i+1] != 0 || data[i+2] != ':' || data[i+3] != 0 || (data[i] != source && data[i] != source+32) {
			continue
		}
		if i > 0 && (data[i-1] != 0 || !driveBoundary(data[i-2])) {
			continue
		}
		if out == nil {
			out = append([]byte(nil), data...)
		}
		out[i] = target
		if data[i] == source+32 {
			out[i] += 32
		}
	}
	if out == nil {
		return data
	}
	return out
}
