package main

// Deliberately allocation-free: DOS code, data, heap and stack share 64 KiB.
// Only ASCII paths/command tails are accepted; arbitrary file bytes use hex.
const lineLimit = 1024

var input [lineLimit + 1]byte
var starts [8]int
var ends [8]int
var fields int

func equalField(index int, value string) bool {
	if index >= fields {
		return false
	}
	start, end := starts[index], ends[index]
	if end-start != len(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if input[start+i] != value[i] {
			return false
		}
	}
	return true
}

// parse validates the entire line before dispatch. Decoding is in place in the
// fixed buffer, including terminators for DOS ASCIIZ paths. No prefix is run.
func parse(n int) bool {
	fields = 0
	if n > 0 && input[n-1] == '\r' {
		n--
	}
	if n == 0 || n > lineLimit {
		return false
	}
	pos := 0
	for i := 0; i <= n; i++ {
		if fields >= len(starts) {
			return false
		}
		starts[fields] = pos
		for i < n && input[i] != '\t' {
			c := input[i]
			if c < 32 || c > 126 {
				return false
			}
			if c == '\\' {
				i++
				if i >= n {
					return false
				}
				c = input[i]
				if c == 't' {
					c = '\t'
				} else if c == 'n' {
					c = '\n'
				} else if c == 'r' {
					c = '\r'
				} else if c != '\\' {
					return false
				}
			}
			input[pos] = c
			pos++
			i++
		}
		ends[fields] = pos
		input[pos] = 0
		pos++
		fields++
	}
	return true
}

func stringArg(index int, maximum int, empty bool) bool {
	if index >= fields {
		return false
	}
	start, end := starts[index], ends[index]
	if end <= start || input[start] != 's' {
		return false
	}
	length := end - start - 1
	if length > maximum || (!empty && length == 0) {
		return false
	}
	for i := start + 1; i < end; i++ {
		if input[i] < 32 || input[i] > 126 {
			return false
		}
	}
	return true
}
func integerArg(index int, maximum int) int {
	if index >= fields {
		return -1
	}
	start, end := starts[index], ends[index]
	if end-start < 2 || input[start] != 'i' {
		return -1
	}
	value := 0
	for i := start + 1; i < end; i++ {
		c := input[i]
		if c < '0' || c > '9' || value > maximum/10 || (value == maximum/10 && int(c-'0') > maximum%10) {
			return -1
		}
		value = value*10 + int(c-'0')
	}
	return value
}
func hexDigit(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c-'a') + 10
	}
	if c >= 'A' && c <= 'F' {
		return int(c-'A') + 10
	}
	return -1
}

var transfer [256]byte

func hexArg(index int) int {
	if !stringArg(index, len(transfer)*2, true) {
		return -1
	}
	start, end := starts[index]+1, ends[index]
	if (end-start)%2 != 0 {
		return -1
	}
	for i := start; i < end; i += 2 {
		a, b := hexDigit(input[i]), hexDigit(input[i+1])
		if a < 0 || b < 0 {
			return -1
		}
		transfer[(i-start)/2] = byte(a*16 + b)
	}
	return (end - start) / 2
}
