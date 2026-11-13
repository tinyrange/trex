package s390

// LineConsole is a line-mode console as interactive frontends see it: an
// append-only transcript and a way to enter a line.
type LineConsole interface {
	// Version changes whenever output or input changes the console.
	Version() uint64
	// Transcript returns the completed lines from absolute line index
	// from (clamped to those retained), the index of the first returned
	// line, and the unterminated current line.
	Transcript(from int) (first int, lines []string, partial string)
	// Enter enters one line as the operator.
	Enter(line string)
	// Waiting reports whether the program is waiting for input.
	Waiting() bool
}

func transcript(lines []string, dropped, from int) (int, []string) {
	if from < dropped {
		from = dropped
	}
	if from > dropped+len(lines) {
		from = dropped + len(lines)
	}
	return from, append([]string(nil), lines[from-dropped:]...)
}

func (t *Console3215) Version() uint64 { return t.version }

func (t *Console3215) Transcript(from int) (int, []string, string) {
	first, lines := transcript(t.Lines, t.dropped, from)
	return first, lines, t.Partial
}

func (t *Console3215) Enter(line string) { t.Type(line) }

// Waiting reports whether a read inquiry is waiting for the operator.
func (t *Console3215) Waiting() bool {
	return t.css != nil && t.css.Waiting(t.devno)
}

// SystemConsole is the hardware system console of the service-call logical
// processor: operating-system messages and operator commands (or the VT220
// console stream, when the program registered only that).
type SystemConsole struct{ m *Machine }

// SystemConsole returns the machine's hardware system console.
func (m *Machine) SystemConsole() *SystemConsole { return &SystemConsole{m} }

func (s *SystemConsole) Version() uint64 { return s.m.sclp.version }

func (s *SystemConsole) Transcript(from int) (int, []string, string) {
	first, lines := transcript(s.m.sclp.Lines, s.m.sclp.dropped, from)
	return first, lines, string(s.m.sclp.Partial)
}

func (s *SystemConsole) Enter(line string) {
	s.m.sclp.version++
	s.m.Command(line)
}

// Waiting reports whether the program accepts operator input at all.
func (s *SystemConsole) Waiting() bool {
	return s.m.sclp.cpReceive&(evMask(evOpCmd)|evMask(evVT220)) != 0
}

// A printer's or punch's output is a read-only line console.

func (u *UnitRecord) Version() uint64 { return u.version }

func (u *UnitRecord) Transcript(from int) (int, []string, string) {
	first, lines := transcript(u.Output, u.dropped, from)
	return first, lines, ""
}

// Enter does nothing: the operator cannot type to a printer.
func (u *UnitRecord) Enter(string) {}

func (u *UnitRecord) Waiting() bool { return false }
