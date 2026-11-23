package kd

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

func EarlyBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("kd_early", args, kwargs, "channel", &value); err != nil {
		return nil, err
	}
	transport, ok := value.(channel.ByteChannel)
	if !ok {
		return nil, fmt.Errorf("kd_early: expected byte channel")
	}
	session, err := NewEarlySession(transport)
	if err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	valueSession := &earlyValue{session: session}
	valueSession.unregister, err = resources.Add(valueSession)
	if err != nil {
		return nil, err
	}
	return valueSession, nil
}

type earlyValue struct {
	session    *EarlySession
	unregister func()
}

func (v *earlyValue) Close() error {
	if v.unregister != nil {
		v.unregister()
	}
	return v.session.Close()
}

func (*earlyValue) String() string        { return "<early NT KD session>" }
func (*earlyValue) Type() string          { return "windows.kd_early" }
func (*earlyValue) Freeze()               {}
func (*earlyValue) Truth() starlark.Bool  { return starlark.True }
func (*earlyValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: windows.kd_early") }

var earlyMethods = []string{"breakin", "close", "context", "continue", "poll", "read_virtual", "reply_prompt", "request", "set_context", "stopped", "write_virtual"}

func (*earlyValue) AttrNames() []string { return slices.Clone(earlyMethods) }
func (v *earlyValue) Attr(name string) (starlark.Value, error) {
	if name == "stopped" {
		return starlark.Bool(v.session.Stopped()), nil
	}
	if slices.Contains(earlyMethods, name) {
		return starlark.NewBuiltin(name, v.call), nil
	}
	return nil, nil
}

func earlyU32(n uint32) starlark.Int { return starlark.MakeUint64(uint64(n)) }

func earlyRegisters(values [32]uint32) starlark.Tuple {
	regs := make(starlark.Tuple, len(values))
	for i, n := range values {
		regs[i] = earlyU32(n)
	}
	return regs
}

func earlyEventValue(e *EarlyEvent) starlark.Value {
	context := starlark.Value(starlark.None)
	if c := e.Context; c != nil {
		context = starvalue.NewRecord(starlark.StringDict{
			"gpr": earlyRegisters(c.GPR), "fpr": earlyRegisters(c.FPR), "lo": earlyU32(c.Lo), "hi": earlyU32(c.Hi),
			"fcsr": earlyU32(c.FCSR), "pc": earlyU32(c.PC), "psr": earlyU32(c.PSR), "flags": earlyU32(c.Flags),
		})
	}
	return starvalue.NewRecord(starlark.StringDict{
		"kind": starlark.String(e.Kind), "type": starlark.MakeInt(int(e.Type)),
		"api": earlyU32(e.API), "processor": earlyU32(e.Processor), "processor_count": earlyU32(e.ProcessorCount),
		"thread": earlyU32(e.Thread), "pc": earlyU32(e.PC), "code": earlyU32(e.Code), "address": earlyU32(e.Address),
		"first_chance": starlark.Bool(e.FirstChance), "status": earlyU32(e.Status), "actual": earlyU32(e.Actual),
		"text": starlark.String(e.Text), "limit": earlyU32(e.Limit), "raw": starlark.Bytes(e.Raw), "data": starlark.Bytes(e.Data), "context": context,
	})
}

func (v *earlyValue) call(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name, s := fn.Name(), v.session
	switch name {
	case "poll":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		ev, err := s.Poll()
		if ev == nil || err != nil {
			return starlark.None, err
		}
		return earlyEventValue(ev), nil
	case "breakin":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return starlark.None, s.BreakIn()
	case "reply_prompt":
		var data starlark.Bytes
		if err := starlark.UnpackArgs(name, args, kwargs, "data", &data); err != nil {
			return nil, err
		}
		return starlark.None, s.ReplyPrompt([]byte(data))
	case "close":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return starlark.None, v.Close()
	}
	var api, processor, arg0, arg1, arg2 uint32
	var payload starlark.Bytes
	switch name {
	case "context":
		api = kdAPIGetContext
		if err := starlark.UnpackArgs(name, args, kwargs, "processor?", &processor); err != nil {
			return nil, err
		}
	case "set_context":
		api = kdAPISetContext
		var pc *uint32
		var pcValue starlark.Value
		if err := starlark.UnpackArgs(name, args, kwargs, "context", &payload, "pc?", &pcValue, "processor?", &processor); err != nil {
			return nil, err
		}
		if pcValue != nil && pcValue != starlark.None {
			var n uint32
			if err := starlark.AsInt(pcValue, &n); err != nil {
				return nil, err
			}
			if n&3 != 0 {
				return nil, fmt.Errorf("early KD: unaligned PC %#x", n)
			}
			pc = &n
		}
		if _, err := ParseMIPSContext([]byte(payload)); err != nil {
			return nil, err
		}
		if pc != nil {
			update := []byte(payload)
			binary.LittleEndian.PutUint32(update[0x11c:], *pc)
			payload = starlark.Bytes(update)
		}
	case "read_virtual":
		api = kdAPIReadVirtual
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &arg0, "size", &arg1, "processor?", &processor); err != nil {
			return nil, err
		}
		if arg1 > earlyPacketLimit-earlyManipulateSize || uint64(arg0)+uint64(arg1) > 1<<32 {
			return nil, fmt.Errorf("early KD: invalid virtual read range")
		}
	case "write_virtual":
		api = kdAPIWriteVirtual
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &arg0, "data", &payload, "processor?", &processor); err != nil {
			return nil, err
		}
		if len(payload) > earlyPacketLimit-earlyManipulateSize || uint64(arg0)+uint64(len(payload)) > 1<<32 {
			return nil, fmt.Errorf("early KD: invalid virtual write range")
		}
		arg1 = uint32(len(payload))
	case "continue":
		api, arg0 = kdAPIContinue, kdContinueStatus
		if err := starlark.UnpackArgs(name, args, kwargs, "status?", &arg0); err != nil {
			return nil, err
		}
	case "request":
		if err := starlark.UnpackArgs(name, args, kwargs, "api", &api, "processor?", &processor,
			"arg0?", &arg0, "arg1?", &arg1, "arg2?", &arg2, "data?", &payload); err != nil {
			return nil, err
		}
	}
	return starlark.None, s.Request(api, processor, arg0, arg1, arg2, []byte(payload))
}
