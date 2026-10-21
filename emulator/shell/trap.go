package shell

import (
	"fmt"
	"sort"
	"strings"
)

func signalName(name string) (string, error) {
	name = strings.TrimPrefix(name, "SIG")
	switch name {
	case "0", "EXIT":
		return "EXIT", nil
	case "1", "HUP":
		return "HUP", nil
	case "2", "INT":
		return "INT", nil
	case "3", "QUIT":
		return "QUIT", nil
	case "13", "PIPE":
		return "PIPE", nil
	case "15", "TERM":
		return "TERM", nil
	}
	return "", unsupported("trap signal " + name)
}
func (s *shell) trap(args []string) error {
	if len(args) == 0 {
		keys := make([]string, 0, len(s.traps))
		for k := range s.traps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := fmt.Fprintf(s.output(1), "trap -- '%s' %s\n", strings.ReplaceAll(s.traps[k], "'", "'\\''"), k); err != nil {
				return err
			}
		}
		return nil
	}
	if args[0] == "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		return fmt.Errorf("trap: expected action and signal")
	}
	for _, name := range args[1:] {
		signal, err := signalName(name)
		if err != nil {
			return err
		}
		if args[0] == "-" {
			delete(s.traps, signal)
		} else {
			s.traps[signal] = args[0]
		}
	}
	return nil
}
func (s *shell) exitTrap() error {
	action, ok := s.traps["EXIT"]
	if !ok || action == "" {
		return nil
	}
	delete(s.traps, "EXIT")
	status, flow := s.status, s.flow
	s.flow = ""
	if err := s.evaluate(action, s.name+":trap", false); err != nil {
		return err
	}
	if s.flow != "exit" {
		s.status = status
		s.flow = flow
	}
	return nil
}
