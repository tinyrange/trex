package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBackgroundSemantics(t *testing.T) {
	cases := []struct {
		name, source, want string
		status             int
	}{
		{"status and isolation", `x=parent; (x=child; exit 7) & p=$!; printf '%s:' "$?"; wait "$p"; printf '%s:%s:' "$?" "$x"; wait "$p"; printf '%s' "$?"`, "0:7:parent:127", 0},
		{"wait all", `(exit 9) & (exit 3) & wait; printf '%s' "$?"`, "0", 0},
		{"wait last", `(exit 9) & a=$!; (exit 3) & b=$!; wait "$a" "$b"`, "", 3},
		{"scoped table", `(exit 9) & p=$!; (wait "$p"); printf '%s:' "$?"; wait "$p"`, "127:", 9},
		{"null stdin", `cat >empty & wait; cat empty; read word; printf '%s' "$word"`, "input", 0},
		{"explicit stdin", `printf file >in; cat <in >out & wait; cat out`, "file", 0},
		{"inherited descriptor", `exec 3>out; { printf first >&3; printf second >&3; } & exec 3>&-; wait; cat out`, "firstsecond", 0},
		{"capture descendant", `v=$( { printf captured; } & ); printf '%s' "$v"`, "captured", 0},
		{"pipe descendant", `{ { printf 'captured\n'; } & } | cat`, "captured\n", 0},
		{"ordinary failure", `set -e; false & wait`, "", 0},
		{"unwaited failure", `false & :`, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			r, err := Run(ctx, strings.NewReader(tc.source), "test", Config{FS: testFS(t), Stdin: strings.NewReader("input\n"), Stdout: &out})
			if err != nil || r.Status != tc.status || out.String() != tc.want {
				t.Fatalf("result=%+v err=%v output=%q", r, err, out.String())
			}
		})
	}
}

func TestBackgroundIsAsynchronous(t *testing.T) {
	// Channel rendezvous proves the foreground proceeds while the job sleeps;
	// there are no timing assertions or fake successful sleeps.
	entered, release := make(chan struct{}), make(chan struct{})
	wait := func(ctx context.Context, d time.Duration) error {
		if d != 1250*time.Millisecond {
			return fmt.Errorf("duration %v", d)
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	handler := func(ctx context.Context, in Invocation) (int, error) {
		if in.Args[0] != "release" {
			return 0, ErrUnhandled
		}
		select {
		case <-entered:
			close(release)
			return 0, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	r, err := Run(ctx, strings.NewReader(`{ sleep 1.25; printf done; } & p=$!; release; wait "$p"`), "test", Config{FS: testFS(t), Sleep: wait, Command: handler, Stdout: &out})
	if err != nil || r.Status != 0 || out.String() != "done" {
		t.Fatalf("%+v %v %q", r, err, out.String())
	}
}

func TestBackgroundFailureAndCancellation(t *testing.T) {
	for _, source := range []string{`jobs & wait`, `jobs & :`, `v=$(jobs &)`} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := Run(ctx, strings.NewReader(source), "test", Config{FS: testFS(t)})
		cancel()
		var gap *UnsupportedError
		if !errors.As(err, &gap) {
			t.Fatalf("%s: %v", source, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	sleeper := func(ctx context.Context, d time.Duration) error {
		cancel()
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	}
	_, err := Run(ctx, strings.NewReader(`sleep 100 & wait`), "test", Config{FS: testFS(t), Sleep: sleeper})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Run returned before job stopped")
	}
}

func TestBackgroundBudget(t *testing.T) {
	_, err := Run(context.Background(), strings.NewReader(`true & true & wait`), "test", Config{FS: testFS(t), MaxJobs: 1})
	if err == nil || !strings.Contains(err.Error(), "job budget") {
		t.Fatal(err)
	}
}

func TestSleepValidation(t *testing.T) {
	for _, source := range []string{"sleep", "sleep -1", "sleep NaN", "sleep 1x", "sleep 1 2", "sleep 99999999999999999", "sleep ."} {
		r, err := Run(context.Background(), strings.NewReader(source), "test", Config{FS: testFS(t), Sleep: func(context.Context, time.Duration) error { t.Fatal("invalid sleep reached clock"); return nil }})
		if err != nil || r.Status == 0 {
			t.Fatalf("%s: %+v %v", source, r, err)
		}
	}
}

func TestBackgroundLifetime(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	handler := func(ctx context.Context, in Invocation) (int, error) {
		switch in.Args[0] {
		case "block":
			close(entered)
			select {
			case <-release:
				return 0, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		case "release":
			select {
			case <-entered:
				close(release)
				return 0, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		return 0, ErrUnhandled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	// A nested shell may return with a live job; the API still drains that job.
	r, e := Run(ctx, strings.NewReader(`({ block; printf done; } &); release`), "test", Config{FS: testFS(t), Command: handler, Stdout: &out})
	if e != nil || r.Status != 0 || out.String() != "done" {
		t.Fatalf("%+v %v %q", r, e, out.String())
	}
}
func TestBackgroundReapReleasesBudget(t *testing.T) {
	r, e := Run(context.Background(), strings.NewReader(`true & wait; true & wait; sleep 0`), "test", Config{FS: testFS(t), MaxJobs: 1})
	if e != nil || r.Status != 0 {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestForegroundFailureCancelsJobs(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	sleeper := func(ctx context.Context, _ time.Duration) error {
		close(started)
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	}
	handler := func(ctx context.Context, in Invocation) (int, error) {
		select {
		case <-started:
			return 0, unsupported("foreground gap")
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, e := Run(ctx, strings.NewReader(`sleep 100 & fail`), "test", Config{FS: testFS(t), Sleep: sleeper, Command: handler})
	var gap *UnsupportedError
	if !errors.As(e, &gap) || gap.Feature != "foreground gap" {
		t.Fatal(e)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("job still running")
	}
}
