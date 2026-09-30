// Package shell executes shell syntax in a virtual Unix environment. It uses
// no host processes, host environment, host filesystem, or operating-system
// pipes. Unsupported semantics are errors, not ordinary command exit statuses.
package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/pattern"
	"mvdan.cc/sh/v3/syntax"
)

// UnsupportedError identifies an emulator gap, which must not be mistaken for
// an ordinary negative feature probe by configure's `if`, `!`, or `||`.
type UnsupportedError struct{ Feature string }

func (e *UnsupportedError) Error() string { return "shell: unsupported " + e.Feature }
func unsupported(feature string) error    { return &UnsupportedError{feature} }

// Invocation is an in-process command request. Env contains only exported
// variables and command-prefix assignments. Its paths are always guest paths.
// Handlers must honor context cancellation and must never invoke host tools.
type Invocation struct {
	// Executable is the guest path resolved by Commands, separate from argv[0].
	Executable string
	Args       []string
	Env        map[string]string
	Dir        string
	FS         FileSystem
	// Umask is the invoking shell's file creation mask, independent of host state.
	Umask          fs.FileMode
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// ErrUnhandled asks the shell to try its virtual PATH/script loader.
var ErrUnhandled = errors.New("shell: command not handled")

type CommandHandler func(context.Context, Invocation) (int, error)

// Config supplies every external capability explicitly. Zero limits select
// conservative defaults; there is no implicit host environment or PATH lookup.
type Config struct {
	FS             FileSystem
	Dir            string
	Env            map[string]string
	Args           []string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Command        CommandHandler
	// Umask defaults to 0022; a non-nil pointer can explicitly select zero.
	Umask                *fs.FileMode
	MaxSteps             int64
	MaxSubstitutionBytes int
	MaxDepth             int
	MaxJobs              int
	// MaxAWKTime bounds each AWK interpreter invocation; default 30 seconds.
	MaxAWKTime time.Duration
	// Sleep supplies a cancellable clock wait; nil uses a portable Go timer.
	Sleep func(context.Context, time.Duration) error
}
type Result struct {
	Status int
	Steps  int64
}
type descriptor struct {
	owner  *fileOwner
	reader io.Reader
	writer io.Writer
}
type execution struct {
	remaining  atomic.Int64
	limit      int64
	nextJob    atomic.Int64
	activeJobs atomic.Int64
	jobs       jobExecution
}
type shell struct {
	cfg                      Config
	ctx                      context.Context
	execution                *execution
	vars                     map[string]expand.Variable
	funcs                    map[string]*syntax.Stmt
	traps                    map[string]string
	fds                      map[int]descriptor
	params                   []string
	dir, name                string
	source                   string
	status, depth            int
	substitutions            int
	flow                     string
	levels                   int
	jobs                     map[int64]*job
	lastJob                  int64
	umask                    fs.FileMode
	errexit, nounset, noglob bool
}

// Run parses POSIX shell source, then executes it in the supplied filesystem.
// Nonzero shell exits are reported in Result, not as emulator errors. All
// handles opened by this execution are closed before Run returns.
func Run(ctx context.Context, source io.Reader, name string, cfg Config) (Result, error) {
	if cfg.FS == nil {
		return Result{}, fmt.Errorf("shell: filesystem is required")
	}
	if cfg.Dir == "" {
		cfg.Dir = "/"
	}
	if err := validPath(cfg.Dir); err != nil {
		return Result{}, err
	}
	st, err := cfg.FS.Stat(cfg.Dir)
	if err != nil {
		return Result{}, err
	}
	if !st.IsDir() {
		return Result{}, fmt.Errorf("shell: working directory is not a directory")
	}
	if cfg.MaxSteps == 0 {
		cfg.MaxSteps = 100000
	}
	if cfg.MaxSubstitutionBytes == 0 {
		cfg.MaxSubstitutionBytes = 8 << 20
	}
	if cfg.MaxJobs == 0 {
		cfg.MaxJobs = 256
	}
	if cfg.Sleep == nil {
		cfg.Sleep = timerSleep
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 128
	}
	if cfg.MaxSteps < 0 || cfg.MaxSubstitutionBytes < 0 || cfg.MaxDepth < 0 || cfg.MaxJobs < 0 {
		return Result{}, fmt.Errorf("shell: budgets must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(source, int64(cfg.MaxSubstitutionBytes)+1))
	if err != nil {
		return Result{}, err
	}
	if len(data) > cfg.MaxSubstitutionBytes {
		return Result{}, fmt.Errorf("shell: source budget exceeded")
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(bytes.NewReader(data), name)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := &execution{limit: cfg.MaxSteps, jobs: jobExecution{cancel: cancel}}
	run.nextJob.Store(1)
	run.remaining.Store(cfg.MaxSteps)
	s := &shell{cfg: cfg, ctx: ctx, execution: run, vars: map[string]expand.Variable{}, funcs: map[string]*syntax.Stmt{}, traps: map[string]string{}, fds: map[int]descriptor{}, params: append([]string(nil), cfg.Args...), dir: cfg.Dir, name: name, source: name}
	s.umask = 0022
	if cfg.Umask != nil {
		if *cfg.Umask&^0777 != 0 {
			return Result{}, fmt.Errorf("shell: invalid creation mask")
		}
		s.umask = *cfg.Umask
	}
	for k, v := range cfg.Env {
		s.vars[k] = expand.Variable{Set: true, Kind: expand.String, Str: v, Exported: true}
	}
	s.vars["PWD"] = expand.Variable{Set: true, Kind: expand.String, Str: s.dir, Exported: true}
	if cfg.Stdin == nil {
		cfg.Stdin = strings.NewReader("")
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	// Callers may share a writer between stdout/stderr and pipeline stages. Serialize
	// access so a bytes.Buffer is safe without requiring callers to wrap it.
	outputMu := new(sync.Mutex)
	defer func() { closeDescriptors(s.fds) }()
	s.fds[0] = descriptor{reader: lockedReader{new(sync.Mutex), cfg.Stdin}}
	s.fds[1] = descriptor{writer: lockedWriter{outputMu, cfg.Stdout}}
	s.fds[2] = descriptor{writer: lockedWriter{outputMu, cfg.Stderr}}
	err = s.list(file.Stmts, false)
	if err == nil {
		err = s.exitTrap()
	}
	if err == nil && s.flow != "" && s.flow != "exit" {
		err = fmt.Errorf("shell: %s outside its enclosing scope", s.flow)
	}
	err = s.finish(err)
	return Result{Status: s.status, Steps: run.limit - run.remaining.Load()}, err
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (w lockedWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(b)
}
func (s *shell) tick() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.execution.remaining.Add(-1) < 0 {
		return fmt.Errorf("shell: statement budget exceeded")
	}
	return nil
}
func (s *shell) child() (*shell, error) {
	if s.depth >= s.cfg.MaxDepth {
		return nil, fmt.Errorf("shell: nesting budget exceeded")
	}
	c := *s
	c.jobs = nil
	c.lastJob = 0
	c.vars = maps.Clone(s.vars)
	c.funcs = maps.Clone(s.funcs)
	c.traps = map[string]string{}
	for signal, action := range s.traps {
		if action == "" {
			c.traps[signal] = action
		}
	}
	c.fds = cloneDescriptors(s.fds)
	c.params = append([]string(nil), s.params...)
	c.depth++
	c.flow = ""
	return &c, nil
}
func (s *shell) resolve(name string) string {
	if path.IsAbs(name) {
		return path.Clean(name)
	}
	return path.Join(s.dir, name)
}
func (s *shell) input() io.Reader {
	if f, ok := s.fds[0]; ok && f.reader != nil {
		return f.reader
	}
	return badReader{}
}
func (s *shell) output(n int) io.Writer {
	if f, ok := s.fds[n]; ok && f.writer != nil {
		return f.writer
	}
	return badWriter{}
}

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, fmt.Errorf("bad input descriptor") }

type badWriter struct{}

func (badWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("bad output descriptor") }
func (s *shell) diagnostic(err error) error {
	_, e := fmt.Fprintln(s.output(2), err)
	s.status = 1
	return e
}

func (s *shell) Get(name string) expand.Variable {
	value := ""
	switch name {
	case "!":
		if s.lastJob == 0 {
			return expand.Variable{}
		}
		value = strconv.FormatInt(s.lastJob, 10)
	case "?":
		value = strconv.Itoa(s.status)
	case "#":
		value = strconv.Itoa(len(s.params))
	case "0":
		value = s.name
	case "$":
		value = "1" // Virtual shell identity, never the host PID.
	case "@", "*":
		return expand.Variable{Set: true, Kind: expand.Indexed, List: append([]string{}, s.params...)}
	case "-":
		if s.errexit {
			value += "e"
		}
		if s.nounset {
			value += "u"
		}
		if s.noglob {
			value += "f"
		}
	default:
		if n, err := strconv.Atoi(name); err == nil && n > 0 {
			if n <= len(s.params) {
				value = s.params[n-1]
			} else {
				return expand.Variable{}
			}
		} else {
			// Override expand's os/user fallback: unknown virtual users remain literal.
			if strings.HasPrefix(name, "HOME ") {
				return expand.Variable{Set: true, Kind: expand.String, Str: "~" + strings.TrimPrefix(name, "HOME ")}
			}
			return s.vars[name]
		}
	}
	return expand.Variable{Set: true, Kind: expand.String, Str: value}
}
func (s *shell) Each(fn func(string, expand.Variable) bool) {
	for k, v := range s.vars {
		if !fn(k, v) {
			break
		}
	}
}
func (s *shell) Set(name string, v expand.Variable) error {
	old := s.vars[name]
	if old.ReadOnly {
		return fmt.Errorf("shell: %s is readonly", name)
	}
	if v.Kind == expand.KeepValue {
		v.Kind, v.Str, v.Set = old.Kind, old.Str, old.Set
	} else {
		v.Exported = v.Exported || old.Exported
	}
	if !v.Declared() {
		delete(s.vars, name)
	} else {
		s.vars[name] = v
	}
	return nil
}
func (s *shell) set(name, value string) error {
	return s.Set(name, expand.Variable{Set: true, Kind: expand.String, Str: value})
}

type limitedBuffer struct {
	bytes.Buffer
	maximum int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.maximum-b.Len() {
		return 0, fmt.Errorf("shell: substitution budget exceeded")
	}
	return b.Buffer.Write(p)
}
func (s *shell) expansion() *expand.Config {
	cfg := &expand.Config{Env: s, NoUnset: s.nounset}
	if !s.noglob {
		cfg.ReadDir2 = func(name string) ([]fs.DirEntry, error) { return s.cfg.FS.ReadDir(s.resolve(name)) }
	}
	cfg.CmdSubst = func(out io.Writer, node *syntax.CmdSubst) error {
		c, err := s.child()
		if err != nil {
			return err
		}
		b := &limitedBuffer{maximum: s.cfg.MaxSubstitutionBytes}
		defer func() { closeDescriptors(c.fds) }()
		end := captureEnd{done: make(chan struct{})}
		c.setDescriptor(1, descriptor{owner: &fileOwner{closer: end}, writer: lockedWriter{new(sync.Mutex), b}})
		if err = c.list(node.Stmts, false); err != nil {
			return err
		}
		if err = c.exitTrap(); err != nil {
			return err
		}
		closeDescriptors(c.fds)
		c.fds = nil
		select {
		case <-end.done:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
		s.status = c.status
		s.substitutions++
		_, err = out.Write(b.Bytes())
		return err
	}
	return cfg
}
func (s *shell) list(stmts []*syntax.Stmt, tested bool) error {
	for _, stmt := range stmts {
		if s.flow != "" {
			break
		}
		if err := s.stmt(stmt, tested); err != nil {
			return err
		}
	}
	return nil
}
func (s *shell) stmt(stmt *syntax.Stmt, tested bool) error {
	if err := s.tick(); err != nil {
		return err
	}
	if stmt.Background {
		return s.background(stmt)
	}
	old := s.fds
	if len(stmt.Redirs) > 0 {
		s.fds = cloneDescriptors(old)
	}
	persist := false
	defer func() {
		if len(stmt.Redirs) > 0 {
			if persist {
				closeDescriptors(old)
			} else {
				closeDescriptors(s.fds)
				s.fds = old
			}
		}
	}()
	for _, r := range stmt.Redirs {
		if err := s.redirect(r); err != nil {
			var fileError *fs.PathError
			if errors.As(err, &fileError) {
				if writeErr := s.diagnostic(err); writeErr != nil {
					return writeErr
				}
				if stmt.Negated {
					s.status = 0
				} else if s.errexit && !tested {
					s.flow = "exit"
				}
				return nil
			}
			return fmt.Errorf("%s:%s: %w", s.source, r.Pos(), err)
		}
	}
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 1 && call.Args[0].Lit() == "exec" {
		persist = true
	}
	err := s.command(stmt.Cmd, tested || stmt.Negated)
	if err != nil {
		return fmt.Errorf("%s:%s: %w", s.source, stmt.Pos(), err)
	}
	if stmt.Negated {
		if s.status == 0 {
			s.status = 1
		} else {
			s.status = 0
		}
	}
	binary, isBinary := stmt.Cmd.(*syntax.BinaryCmd)
	andOr := isBinary && (binary.Op == syntax.AndStmt || binary.Op == syntax.OrStmt)
	if s.errexit && !andOr && !tested && !stmt.Negated && s.status != 0 && s.flow == "" {
		s.flow = "exit"
	}
	return nil
}
func (s *shell) redirect(r *syntax.Redirect) error {
	n := 1
	if r.Op == syntax.RdrIn || r.Op == syntax.DplIn || r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc || r.Op == syntax.RdrInOut {
		n = 0
	}
	if r.N != nil {
		v, err := strconv.Atoi(r.N.Value)
		if err != nil || v < 0 || v > 1024 {
			return unsupported("descriptor " + r.N.Value)
		}
		n = v
	}
	if r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc {
		word := r.Hdoc
		if r.Op == syntax.DashHdoc {
			word = stripHeredocTabs(word)
		}
		var body string
		var err error
		if quotedHeredoc(r.Word) {
			body = word.Lit()
		} else {
			body, err = s.document(word)
		}
		if err != nil {
			return err
		}
		s.setDescriptor(n, descriptor{reader: lockedReader{new(sync.Mutex), strings.NewReader(body)}})
		return nil
	}
	name, err := s.literal(r.Word)
	if err != nil {
		return err
	}
	if r.Op == syntax.DplOut || r.Op == syntax.DplIn {
		if name == "-" {
			s.closeDescriptor(n)
			return nil
		}
		other, err := strconv.Atoi(name)
		if err != nil {
			return fmt.Errorf("bad descriptor %q", name)
		}
		d, ok := s.fds[other]
		if !ok {
			return fmt.Errorf("bad descriptor %d", other)
		}
		s.setDescriptor(n, d)
		return nil
	}
	var flags OpenFlags
	switch r.Op {
	case syntax.RdrOut, syntax.ClbOut:
		flags = Write | Create | Truncate
	case syntax.AppOut:
		flags = Write | Create | Append
	case syntax.RdrIn:
		flags = Read
	case syntax.RdrInOut:
		flags = Read | Write | Create
	default:
		return unsupported("redirection " + r.Op.String())
	}
	f, err := s.open(s.resolve(name), flags, 0666)
	if err != nil {
		return err
	}
	d := descriptor{owner: &fileOwner{closer: f}}
	if flags&Read != 0 {
		d.reader = f
	}
	if flags&Write != 0 {
		d.writer = f
	}
	s.setDescriptor(n, d)
	return nil
}
func (s *shell) command(cmd syntax.Command, tested bool) error {
	switch c := cmd.(type) {
	case nil:
		s.status = 0
		return nil
	case *syntax.CallExpr:
		return s.call(c, tested)
	case *syntax.Block:
		return s.list(c.Stmts, tested)
	case *syntax.Subshell:
		child, err := s.child()
		if err != nil {
			return err
		}
		defer func() { closeDescriptors(child.fds) }()
		err = child.list(c.Stmts, tested)
		if err == nil {
			err = child.exitTrap()
		}
		s.status = child.status
		return err
	case *syntax.FuncDecl:
		s.funcs[c.Name.Value] = c.Body
		s.status = 0
		return nil
	case *syntax.IfClause:
		for clause := c; clause != nil; clause = clause.Else {
			if err := s.list(clause.Cond, true); err != nil {
				return err
			}
			if s.flow != "" {
				return nil
			}
			if len(clause.Cond) == 0 || s.status == 0 {
				return s.list(clause.Then, tested)
			}
		}
		s.status = 0
		return nil
	case *syntax.WhileClause:
		last := 0
		for {
			if err := s.tick(); err != nil {
				return err
			}
			if err := s.list(c.Cond, true); err != nil {
				return err
			}
			if s.flow != "" {
				return nil
			}
			if (s.status == 0) == c.Until {
				break
			}
			if err := s.list(c.Do, tested); err != nil {
				return err
			}
			last = s.status
			stop := s.loopFlow()
			if stop {
				break
			}
		}
		s.status = last
		return nil
	case *syntax.ForClause:
		loop, ok := c.Loop.(*syntax.WordIter)
		if !ok || c.Select {
			return unsupported("non-POSIX for loop")
		}
		words := append([]string(nil), s.params...)
		var err error
		if loop.InPos.IsValid() {
			words, err = s.fields(loop.Items...)
			if err != nil {
				return err
			}
		}
		s.status = 0
		for _, word := range words {
			if err = s.tick(); err != nil {
				return err
			}
			if err = s.set(loop.Name.Value, word); err != nil {
				return err
			}
			if err = s.list(c.Do, tested); err != nil {
				return err
			}
			if s.loopFlow() {
				break
			}
		}
		return nil
	case *syntax.CaseClause:
		value, err := s.literal(c.Word)
		if err != nil {
			return err
		}
		for _, item := range c.Items {
			for _, word := range item.Patterns {
				pat, err := s.pattern(word)
				if err != nil {
					return err
				}
				expr, err := pattern.Regexp(pat, 0)
				if err != nil {
					return err
				}
				matched, err := regexp.MatchString("^(?:"+expr+")$", value)
				if err != nil {
					return err
				}
				if matched {
					return s.list(item.Stmts, tested)
				}
			}
		}
		s.status = 0
		return nil
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe {
			return s.pipeline(c, tested)
		}
		if c.Op != syntax.AndStmt && c.Op != syntax.OrStmt {
			return unsupported("binary operator " + c.Op.String())
		}
		if err := s.stmt(c.X, true); err != nil {
			return err
		}
		if s.flow != "" {
			return nil
		}
		if (c.Op == syntax.AndStmt && s.status == 0) || (c.Op == syntax.OrStmt && s.status != 0) {
			return s.stmt(c.Y, tested)
		}
		return nil
	default:
		return unsupported(fmt.Sprintf("syntax %T", cmd))
	}
}
func (s *shell) loopFlow() bool {
	switch s.flow {
	case "break", "continue":
		flow := s.flow
		s.levels--
		if s.levels == 0 {
			s.flow = ""
		} else {
			return true
		}
		return flow == "break"
	case "":
		return false
	default:
		return true
	}
}
func (s *shell) pipeline(c *syntax.BinaryCmd, tested bool) error {
	left, err := s.child()
	if err != nil {
		return err
	}
	defer func() { closeDescriptors(left.fds) }()
	right, err := s.child()
	if err != nil {
		return err
	}
	defer func() { closeDescriptors(right.fds) }()
	ctx := s.ctx
	reader, writer := io.Pipe() // Go memory pipe, not os.Pipe.
	defer reader.Close()
	defer writer.Close()
	left.setDescriptor(1, descriptor{owner: &fileOwner{closer: writer}, writer: pipeOutput{writer}})
	right.setDescriptor(0, descriptor{reader: reader})
	stop := context.AfterFunc(ctx, func() { reader.CloseWithError(ctx.Err()); writer.CloseWithError(ctx.Err()) })
	defer stop()
	done := make(chan error, 1)
	go func() {
		e := left.stmt(c.X, true)
		closeDescriptors(left.fds)
		left.fds = nil
		if e != nil {
			writer.CloseWithError(e)
		}
		done <- e
	}()
	rightErr := right.stmt(c.Y, tested)
	reader.Close()
	leftErr := <-done
	s.status = right.status
	if leftErr != nil && !errors.Is(leftErr, io.ErrClosedPipe) {
		return leftErr
	}
	return rightErr
}
func (s *shell) call(c *syntax.CallExpr, tested bool) error {
	// Argument expansion precedes temporary prefix assignments.
	beforeSubstitutions := s.substitutions
	args, err := s.fields(c.Args...)
	if err != nil {
		return err
	}
	saved := map[string]expand.Variable{}
	temporary := len(args) > 0 && !specialBuiltin(args[0])
	if temporary {
		defer func() {
			for k, v := range saved {
				if v.Declared() {
					s.vars[k] = v
				} else {
					delete(s.vars, k)
				}
			}
		}()
	}
	subStatus := s.status
	for _, a := range c.Assigns {
		if a.Array != nil || a.Index != nil || a.Append {
			return unsupported("array/append assignment")
		}
		if len(args) > 0 {
			if _, ok := saved[a.Name.Value]; !ok {
				saved[a.Name.Value] = s.vars[a.Name.Value]
			}
		}
		value, err := s.literal(a.Value)
		if err != nil {
			return err
		}
		if err = s.set(a.Name.Value, value); err != nil {
			return err
		}
		if len(args) > 0 {
			v := s.vars[a.Name.Value]
			v.Exported = true
			s.vars[a.Name.Value] = v
		}
	}
	if len(args) == 0 {
		if s.substitutions == beforeSubstitutions {
			s.status = 0
		}
		return nil
	}
	s.status = subStatus
	if body, ok := s.funcs[args[0]]; ok {
		if s.depth >= s.cfg.MaxDepth {
			return fmt.Errorf("shell: nesting budget exceeded")
		}
		params := s.params
		s.params = append([]string(nil), args[1:]...)
		s.depth++
		defer func() { s.params = params; s.depth-- }()
		err := s.stmt(body, tested)
		if s.flow == "return" {
			s.flow = ""
		}
		return err
	}
	return s.dispatch(args, tested)
}
