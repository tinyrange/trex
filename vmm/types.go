// Package vmm defines backend-neutral virtual-machine intent and session
// contracts.
package vmm

import (
	"context"
	"time"

	"github.com/tinyrange/trex/block"
)

type ErrorCode string

const (
	ErrorUnsupported ErrorCode = "unsupported"
	ErrorInvalid     ErrorCode = "invalid"
	ErrorState       ErrorCode = "invalid_state"
	ErrorGuest       ErrorCode = "guest_failure"
	ErrorTimeout     ErrorCode = "timeout"
	ErrorBackend     ErrorCode = "backend_failure"
	ErrorRuntime     ErrorCode = "runtime_failure"
)

type Error struct {
	Code    ErrorCode
	Message string
	Detail  string
	Err     error
}

func (e *Error) Error() string {
	message := string(e.Code) + ": " + e.Message
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}
func (e *Error) Unwrap() error { return e.Err }

type ValidationIssue struct {
	Code, Field, Message, Backend string
}

type Disk struct {
	Device   block.Device
	Name     string
	Bus      string
	Media    string
	Unit     int
	CHS      *CHSGeometry
	ReadOnly bool
	Snapshot bool
	Required bool
}

type CHSGeometry struct{ Cylinders, Heads, Sectors int }
type Network struct {
	Kind, Name string
	Required   bool
}
type Display struct {
	Mode     string
	Required bool
}
type Channel struct {
	Kind, Name string
	Required   bool
}

type Machine struct {
	Architecture         string
	Memory               int64
	CPUs                 int
	Disks                []Disk
	Networks             []Network
	Display              Display
	Channels             []Channel
	StartPaused          bool
	RequiredCapabilities []string
}

type Backend interface {
	ID() string
	Capabilities() []string
	Validate(Machine) []ValidationIssue
	Start(context.Context, Machine) (Driver, error)
}

type State struct {
	Name    string
	Running bool
}

type Result struct {
	Reason   string
	Code     int
	Clean    bool
	Backend  string
	Detail   string
	Finished time.Time
}

type Event struct {
	Kind      string
	Timestamp time.Time
	Backend   string
	Payload   any
}

type Input struct {
	Kind     string
	Key      string
	Down     bool
	Keys     []string
	Text     string
	X, Y     float64
	Absolute bool
	Buttons  []string
	Wheel    int
}

type Driver interface {
	BackendID() string
	Capabilities() []string
	Status(context.Context) (State, error)
	Wait(context.Context) (Result, error)
	NextEvent(context.Context) (Event, error)
	Close(context.Context) error
}
