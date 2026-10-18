package cc

import (
	"errors"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

type hyperVTestCPU struct {
	cpuidTestCPU
	hv  []x86state.CPUIDEntry
	err error
}

func (c *hyperVTestCPU) SupportedHyperVCPUID() ([]x86state.CPUIDEntry, error) { return c.hv, c.err }
func TestHyperVClockPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		long     bool
		features uint32
		err      error
		want     bool
	}{
		{"supported", true, 0xffffffff, nil, true},
		{"legacy", false, 0xffffffff, nil, false},
		{"missing-reference-page", true, 1<<1 | 1<<5, nil, false},
		{"unavailable", true, 0, nil, false},
		{"query-failed", true, 0, errors.New("ioctl failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &hyperVTestCPU{cpuidTestCPU: cpuidTestCPU{input: []x86state.CPUIDEntry{
				{Function: 0, Eax: 3}, {Function: 1}, {Function: 0x80000001, Edx: 1 << 29},
			}}, hv: []x86state.CPUIDEntry{{Function: 0x40000003, Eax: tc.features, Ebx: 0xffffffff, Ecx: 0xffffffff, Edx: 0xffffffff}}, err: tc.err}
			err := configureCPUArchitecture(c, tc.long)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("lost discovery error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			present, leaf := false, false
			for _, e := range c.output {
				if e.Function == 1 {
					present = e.Ecx&(1<<31) != 0
				}
				if e.Function == 0x40000003 {
					leaf = true
					if e.Eax != 1<<1|1<<5|1<<9 || e.Ebx != 0 || e.Ecx != 0 || e.Edx != 0 {
						t.Fatalf("unconfigured features leaked: %+v", e)
					}
				}
			}
			if present != tc.want || leaf != tc.want {
				t.Fatalf("hypervisor=%v leaf=%v want=%v", present, leaf, tc.want)
			}
		})
	}
}

type hyperVTimerTestCPU struct {
	hyperVTestCPU
	enabled   bool
	enableErr error
	calls     int
}

func (c *hyperVTimerTestCPU) EnableHyperVSynIC() (bool, error) {
	c.calls++
	return c.enabled, c.enableErr
}
func TestHyperVTimerPrerequisites(t *testing.T) {
	const clock = 1<<1 | 1<<5 | 1<<9
	const timers = 1<<2 | 1<<3 | 1<<6
	for _, tc := range []struct {
		name     string
		features uint32
		enabled  bool
		err      error
		want     bool
		calls    int
	}{
		{"enabled", clock | timers, true, nil, true, 1},
		{"no-vp-index", clock | 1<<2 | 1<<3, true, nil, false, 0},
		{"no-clock", timers, true, nil, false, 0},
		{"no-capability", clock | timers, false, nil, false, 1},
		{"activation-failed", clock | timers, false, errors.New("enable failed"), false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &hyperVTimerTestCPU{hyperVTestCPU: hyperVTestCPU{hv: []x86state.CPUIDEntry{{Function: 0x40000003, Eax: tc.features, Edx: 0xffffffff}}}, enabled: tc.enabled, enableErr: tc.err}
			entries, err := hyperVClockCPUID(c)
			if c.calls != tc.calls {
				t.Fatalf("activation calls %d want %d", c.calls, tc.calls)
			}
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("lost activation error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var eax, edx uint32
			for _, e := range entries {
				if e.Function == 0x40000003 {
					eax, edx = e.Eax, e.Edx
				}
			}
			if (eax&timers == timers) != tc.want {
				t.Fatalf("timer advertisement %#x", eax)
			}
			if tc.want && edx != 1<<19 || !tc.want && edx != 0 {
				t.Fatalf("unconfigured direct timer: %#x", edx)
			}
		})
	}
}
