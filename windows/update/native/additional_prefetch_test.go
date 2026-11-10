package native

import (
	"errors"
	"testing"
	"time"

	"github.com/tinyrange/trex/windows/uup"
)

func TestAdditionalStagePrefetchBoundOrderAndJoin(t *testing.T) {
	started := make(chan string, 3)
	gates := map[string]chan struct{}{"first": make(chan struct{}), "second": make(chan struct{}), "third": make(chan struct{})}
	// Always unblock workers if an assertion fails.
	defer func() {
		for _, gate := range gates {
			select {
			case <-gate:
			default:
				close(gate)
			}
		}
	}()
	wantErr := errors.New("corrupt second package")
	first := &uup.CumulativeStage{MetadataName: "first"}
	batch := prefetchAdditionalStages([]additionalCabinet{{feature: "first"}, {feature: "second"}, {feature: "third"}}, func(input additionalCabinet) (*uup.CumulativeStage, error) {
		started <- input.feature
		<-gates[input.feature]
		if input.feature == "second" {
			return nil, wantErr
		}
		if input.feature == "first" {
			return first, nil
		}
		return &uup.CumulativeStage{MetadataName: input.feature}, nil
	})
	receive := func() string {
		t.Helper()
		select {
		case name := <-started:
			return name
		case <-time.After(5 * time.Second):
			t.Fatal("parser did not start")
			return ""
		}
	}
	a, b := receive(), receive()
	if a == b || a == "third" || b == "third" {
		t.Fatalf("first workers: %q %q", a, b)
	}
	select {
	case name := <-started:
		t.Fatalf("third parser exceeded bound: %s", name)
	default:
	}
	// Later completion must not replace an earlier stage, and errors retain
	// their identity despite out-of-order completion.
	close(gates["second"])
	if _, err := batch.get("second"); !errors.Is(err, wantErr) {
		t.Fatalf("error: %v", err)
	}
	if name := receive(); name != "third" {
		t.Fatalf("next: %s", name)
	}
	joined := make(chan struct{})
	go func() { batch.join(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("join returned with active readers")
	default:
	}
	close(gates["first"])
	if got, err := batch.get("first"); got != first || err != nil {
		t.Fatalf("first result: %p %v", got, err)
	}
	close(gates["third"])
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("join did not finish")
	}
	if got, err := batch.get("third"); err != nil || got.MetadataName != "third" {
		t.Fatalf("third: %v %v", got, err)
	}
}
