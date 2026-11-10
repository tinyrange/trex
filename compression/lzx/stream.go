package lzx

import (
	"fmt"
	"io"
)

// DecompressTo decodes a CAB LZX stream to dst without retaining the complete
// expanded output. It uses at most two history windows plus one LZX block
// (whose 24-bit size is bounded by the format), and one transformed frame.
// On error dst may contain a prefix; callers must not publish partial output.
func DecompressTo(dst io.Writer, data []byte, windowBits, outSize int) error {
	return decompressTo(dst, newLZXBitReader(data), windowBits, outSize)
}

func decompressTo(dst io.Writer, br *lzxBitReader, windowBits, outSize int) error {
	if outSize < 0 {
		return fmt.Errorf("lzx: negative output size")
	}
	dec, err := newLZXDecoder(windowBits)
	if err != nil {
		return err
	}
	if br.readBits(1) == 1 {
		hi, lo := br.readBits(16), br.readBits(16)
		dec.intelSize = int32((hi << 16) | lo)
	}
	history := make([]byte, 0, min(outSize, 2*dec.windowSize+lzxFrameSize))
	frame := make([]byte, lzxFrameSize)
	base, emitted := 0, 0
	for base+len(history) < outSize {
		if err := dec.decodeBlock(br, &history, outSize-base); err != nil {
			return err
		}
		end := base + len(history)
		complete := end / lzxFrameSize * lzxFrameSize
		if end == outSize {
			complete = end
		}
		for emitted < complete {
			n := min(lzxFrameSize, complete-emitted)
			copy(frame[:n], history[emitted-base:emitted-base+n])
			// Never transform match history. Before intelStarted, no E8 byte can
			// have been emitted: literals enable it, as do uncompressed blocks.
			dec.undoCABFrame(frame[:n], emitted)
			written, err := dst.Write(frame[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
			emitted += n
		}
		// Amortize history copies, preserving an entire window and frame-relative
		// alignment. A partial output frame is always inside the retained window.
		trim := (len(history) - dec.windowSize) / lzxFrameSize * lzxFrameSize
		if trim >= dec.windowSize {
			copy(history, history[trim:])
			history = history[:len(history)-trim]
			base += trim
		}
	}
	return nil
}
