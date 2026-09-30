package shell

import (
	"fmt"
	"io"
	"strings"
)

// wc counts bytes, newlines and C-locale words in a streaming pass.
func (s *shell) wc(args []string) error {
	var lines, words, chars bool
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		for _, c := range arg[1:] {
			switch c {
			case 'l':
				lines = true
			case 'w':
				words = true
			case 'c':
				chars = true
			default:
				return unsupported("wc option " + arg)
			}
		}
	}
	if !lines && !words && !chars {
		lines = true
		words = true
		chars = true
	}
	named := len(args) > 0
	if !named {
		args = []string{"-"}
	}
	var total [3]int64
	emit := func(count [3]int64, name string) error {
		var fields []string
		for i, yes := range []bool{lines, words, chars} {
			if yes {
				fields = append(fields, fmt.Sprint(count[i]))
			}
		}
		if name != "" {
			fields = append(fields, name)
		}
		_, err := fmt.Fprintln(s.output(1), strings.Join(fields, " "))
		return err
	}
	for _, name := range args {
		if err := s.tick(); err != nil {
			return err
		}
		var input io.Reader = s.input()
		var file io.ReadWriteCloser
		if name != "-" {
			var err error
			file, err = s.cfg.FS.Open(s.resolve(name), Read)
			if err != nil {
				if err = s.diagnostic(err); err != nil {
					return err
				}
				continue
			}
			input = file
		}
		var count [3]int64
		inWord := false
		buf := make([]byte, 32768)
		for {
			n, err := input.Read(buf)
			count[2] += int64(n)
			for _, b := range buf[:n] {
				if b == '\n' {
					count[0]++
				}
				space := b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
				if !space && !inWord {
					count[1]++
				}
				inWord = !space
			}
			if err != nil {
				if file != nil {
					file.Close()
				}
				if err != io.EOF {
					return err
				}
				break
			}
			if err = s.tick(); err != nil {
				if file != nil {
					file.Close()
				}
				return err
			}
		}
		for i := range total {
			total[i] += count[i]
		}
		label := ""
		if named {
			label = name
		}
		if err := emit(count, label); err != nil {
			return err
		}
	}
	if len(args) > 1 {
		return emit(total, "total")
	}
	return nil
}
