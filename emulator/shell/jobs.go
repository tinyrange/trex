package shell

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// A job's result is published by closing done. Only its owning shell can wait
// for it; subprocess environments do not inherit the parent's job table.
type job struct {
	done   chan struct{}
	status int
	err    error
}
type jobExecution struct {
	group  sync.WaitGroup
	mu     sync.Mutex
	err    error
	cancel context.CancelFunc
}

func (e *execution) jobError(err error) {
	if err == nil {
		return
	}
	e.jobs.mu.Lock()
	if e.jobs.err == nil {
		e.jobs.err = err
	}
	e.jobs.mu.Unlock()
	e.jobs.cancel()
}
func (s *shell) background(stmt *syntax.Stmt) error {
	if len(s.jobs) >= s.cfg.MaxJobs {
		return fmt.Errorf("shell: retained job budget exceeded")
	}
	if s.execution.activeJobs.Add(1) > int64(s.cfg.MaxJobs) {
		s.execution.activeJobs.Add(-1)
		return fmt.Errorf("shell: active job budget exceeded")
	}
	child, err := s.child()
	if err != nil {
		s.execution.activeJobs.Add(-1)
		return err
	}
	// Noninteractive asynchronous lists get null stdin before explicit redirects.
	child.setDescriptor(0, descriptor{reader: strings.NewReader("")})
	copy := *stmt
	copy.Background = false
	id := s.execution.nextJob.Add(1)
	j := &job{done: make(chan struct{})}
	if s.jobs == nil {
		s.jobs = make(map[int64]*job)
	}
	s.jobs[id] = j
	s.lastJob = id
	s.status = 0
	s.execution.jobs.group.Add(1)
	go func() {
		defer s.execution.jobs.group.Done()
		j.err = child.stmt(&copy, false)
		if j.err == nil {
			j.err = child.exitTrap()
		}
		j.status = child.status
		closeDescriptors(child.fds)
		s.execution.activeJobs.Add(-1)
		s.execution.jobError(j.err)
		close(j.done)
	}()
	return nil
}
func (s *shell) waitJob(id int64) error {
	j, ok := s.jobs[id]
	if !ok {
		s.status = 127
		return nil
	}
	select {
	case <-j.done:
		delete(s.jobs, id)
		s.status = j.status
		return j.err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *shell) wait(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		ids := make([]int64, 0, len(s.jobs))
		for id := range s.jobs {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			if err := s.waitJob(id); err != nil {
				return err
			}
		}
		s.status = 0
		return nil
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "%") {
			return unsupported("wait operand " + arg)
		}
		id, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || id <= 0 {
			s.status = 127
			continue
		}
		if err := s.waitJob(id); err != nil {
			return err
		}
	}
	return nil
}

// timerSleep is the default portable timer capability. Callers may supply a
// virtual clock through Config.Sleep; it must block until expiry/cancellation.
func timerSleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (s *shell) sleep(args []string) error {
	if len(args) != 1 {
		return s.diagnostic(fmt.Errorf("sleep: expected one duration in seconds"))
	}
	// Decimal seconds, no exponents, signs or host-specific suffixes.
	value := args[0]
	whole, fraction, dot := strings.Cut(value, ".")
	if whole == "" {
		whole = "0"
	}
	if value == "" || value == "." || len(fraction) > 9 || dot && fraction == "" {
		return s.diagnostic(fmt.Errorf("sleep: invalid duration %q", value))
	}
	for _, part := range []string{whole, fraction} {
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return s.diagnostic(fmt.Errorf("sleep: invalid duration %q", value))
			}
		}
	}
	duration, err := time.ParseDuration(whole + "." + fraction + "s")
	if err != nil {
		return s.diagnostic(fmt.Errorf("sleep: invalid duration %q", value))
	}
	return s.cfg.Sleep(s.ctx, duration)
}

// Join all remaining work at the public API boundary. A failed foreground
// command cancels jobs; successful shell completion drains them without changing
// its status. No job may access caller resources after Run returns.
func (s *shell) finish(err error) error {
	if err != nil {
		s.execution.jobs.cancel()
	}
	s.execution.jobs.group.Wait()
	s.execution.jobs.mu.Lock()
	jobErr := s.execution.jobs.err
	s.execution.jobs.mu.Unlock()
	if err != nil && errors.Is(jobErr, context.Canceled) {
		return err
	}
	if errors.Is(err, context.Canceled) && jobErr != nil {
		return jobErr
	}
	return errors.Join(err, jobErr)
}
