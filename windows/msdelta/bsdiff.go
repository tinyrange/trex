package msdelta

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// applyBSDiff reconstructs the MSDelta three-control binary-delta variant.
// Each block contains signed-magnitude (add length, insert length, source seek)
// values, followed by additive difference bytes and literal insertion bytes.
func applyBSDiff(source []byte, targetSize uint64, patch []byte) ([]byte, error) {
	if targetSize > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("msdelta: binary-delta target is too large")
	}
	target := make([]byte, int(targetSize))
	patchOffset, targetOffset := 0, 0
	var sourceOffset int64
	for targetOffset < len(target) {
		if len(patch)-patchOffset < 24 {
			return nil, errors.New("msdelta: truncated binary-delta control tuple")
		}
		addLength64 := readBSDiffInt(patch[patchOffset : patchOffset+8])
		insertLength64 := readBSDiffInt(patch[patchOffset+8 : patchOffset+16])
		seek := readBSDiffInt(patch[patchOffset+16 : patchOffset+24])
		patchOffset += 24
		if addLength64 < 0 || insertLength64 < 0 {
			return nil, errors.New("msdelta: negative binary-delta length")
		}
		addLength, insertLength := uint64(addLength64), uint64(insertLength64)
		remainingTarget := uint64(len(target) - targetOffset)
		if addLength > remainingTarget {
			return nil, fmt.Errorf("msdelta: binary-delta add length %d exceeds remaining target %d", addLength, remainingTarget)
		}
		if addLength > uint64(len(patch)-patchOffset) {
			return nil, errors.New("msdelta: truncated binary-delta difference data")
		}
		for index := uint64(0); index < addLength; index++ {
			var sourceByte byte
			if sourceOffset <= int64(^uint64(0)>>1)-int64(index) {
				sourceIndex := sourceOffset + int64(index)
				if sourceIndex >= 0 && uint64(sourceIndex) < uint64(len(source)) {
					sourceByte = source[sourceIndex]
				}
			}
			target[targetOffset+int(index)] = sourceByte + patch[patchOffset+int(index)]
		}
		patchOffset += int(addLength)
		targetOffset += int(addLength)

		remainingTarget = uint64(len(target) - targetOffset)
		if insertLength > remainingTarget {
			return nil, fmt.Errorf("msdelta: binary-delta insert length %d exceeds remaining target %d", insertLength, remainingTarget)
		}
		if insertLength > uint64(len(patch)-patchOffset) {
			return nil, errors.New("msdelta: truncated binary-delta insertion data")
		}
		copy(target[targetOffset:targetOffset+int(insertLength)], patch[patchOffset:patchOffset+int(insertLength)])
		patchOffset += int(insertLength)
		targetOffset += int(insertLength)

		next, ok := addInt64(sourceOffset, addLength64)
		if !ok {
			return nil, errors.New("msdelta: binary-delta source position overflow")
		}
		sourceOffset, ok = addInt64(next, seek)
		if !ok {
			return nil, errors.New("msdelta: binary-delta source seek overflow")
		}
	}
	if patchOffset != len(patch) {
		return nil, fmt.Errorf("msdelta: binary delta has %d trailing bytes", len(patch)-patchOffset)
	}
	return target, nil
}

func readBSDiffInt(data []byte) int64 {
	value := binary.LittleEndian.Uint64(data)
	magnitude := int64(value & uint64(^uint64(0)>>1))
	if value>>63 != 0 {
		return -magnitude
	}
	return magnitude
}

func addInt64(left, right int64) (int64, bool) {
	if right > 0 && left > int64(^uint64(0)>>1)-right {
		return 0, false
	}
	if right < 0 && left < int64(-1<<63)-right {
		return 0, false
	}
	return left + right, true
}
