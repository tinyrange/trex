package r3000

import (
	"encoding/binary"
	"testing"
)

func TestIP24IdleBatchesPreserveTimerBoundary(t *testing.T) {
	for _, timer := range []string{"compare", "pit"} {
		t.Run(timer, func(t *testing.T) {
			m, err := newIP24(nil, false)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			m.cpu.pc, m.cpu.next = mipsWord(0x88000000), mipsWord(0x88000004)
			m.cpu.cp0[status] = 1
			m.cycles = 1
			m.cpu.cp0[6], m.cpu.cp0[1] = 9, 17
			switch timer {
			case "compare":
				m.cpu.cp0[status] |= 1 << 15
				m.cpu.cp0[9], m.cpu.cp0[11] = 0xfffffe00, 4096
			case "pit":
				m.cpu.cp0[status] |= 1 << 12
				m.int3.counter[2] = ip12Counter{reload: 5, count: 5, mode: 3}
				m.int3.counter[0] = ip12Counter{reload: 23, count: 23, mode: 2}
			}
			binary.BigEndian.PutUint32(m.ram, 0x1000ffff) // b .
			want := m.copyState()
			defer want.Close()
			gotStop, gotErr := m.runWithLoopAcceleration(t.Context(), 40000, 1, true)
			wantStop, wantErr := want.runWithLoopAcceleration(t.Context(), 40000, 1, false)
			if gotErr != nil || wantErr != nil || gotStop != wantStop || gotStop.Kind != "exception" {
				t.Fatalf("stop got %+v %v, want %+v %v", gotStop, gotErr, wantStop, wantErr)
			}
			if m.cycles != want.cycles || m.cpu != want.cpu || m.int3 != want.int3 {
				t.Fatalf("batched and single-step state differ at %d clocks", m.cycles)
			}
		})
	}
}

func TestIP24CountdownBatchesMatchInterpreter(t *testing.T) {
	for _, delay := range []bool{false, true} {
		m, err := newIP24(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		m.cpu.pc, m.cpu.next = mipsWord(0x88000000), mipsWord(0x88000004)
		m.cpu.cp0[status] = 0
		m.cpu.gpr[4], m.cpu.gpr[5] = 80003, 5
		binary.BigEndian.PutUint32(m.ram, 0x1c80ffff)     // bgtz a0, .
		binary.BigEndian.PutUint32(m.ram[4:], 0x00852023) // subu a0, a0, a1
		if delay {
			m.cpu.pc, m.cpu.next, m.cpu.delaySlot = m.cpu.next, m.cpu.pc, true
		}
		want := m.copyState()
		t.Cleanup(func() { _ = want.Close() })
		if got := m.batchLoop(false, 31289); got == 0 {
			t.Fatal("countdown was not recognized")
		} else if _, err := want.runWithLoopAcceleration(t.Context(), got, 0, false); err != nil {
			t.Fatal(err)
		}
		if m.cpu != want.cpu || m.cycles != want.cycles {
			t.Fatalf("delay slot %t: batched and single-step state differ", delay)
		}
	}
}

func TestIP24IdleProbeRejectsChangingRAM(t *testing.T) {
	m, err := newIP24(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.cpu.pc, m.cpu.next = mipsWord(0x88000000), mipsWord(0x88000004)
	m.cpu.gpr[4], m.cpu.gpr[5] = mipsWord(0x88000040), 1
	binary.BigEndian.PutUint32(m.ram, 0x1000ffff)     // b .
	binary.BigEndian.PutUint32(m.ram[4:], 0xac850000) // sw a1, (a0)
	if got := m.repeatingLoop(10000); got != 0 || m.ram[0x43] != 0 {
		t.Fatalf("probe skipped %d cycles or changed RAM", got)
	}
}

func TestIP24IdleProbeAllowsRevertedRAMWrites(t *testing.T) {
	m, err := newIP24(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.cpu.pc, m.cpu.next = mipsWord(0x88000000), mipsWord(0x88000004)
	m.cpu.gpr[4], m.cpu.gpr[5] = mipsWord(0x88000040), 1
	for index, word := range []uint32{
		0xac850000, // sw a1, (a0)
		0x8c860000, // lw a2, (a0)
		0x10c50001, // beq a2, a1, +1
		0x00003021, // addu a2, zero, zero
		0x1000fffb, // b loop
		0xac800000, // sw zero, (a0)
	} {
		binary.BigEndian.PutUint32(m.ram[index*4:], word)
	}
	if got := m.repeatingLoop(600); got != 600 || m.ram[0x43] != 0 {
		t.Fatalf("probe skipped %d cycles or changed RAM", got)
	}
}

func TestIP24ScheduledIRQWakesOnSerialInput(t *testing.T) {
	m, err := newIP24(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.cpu.pc, m.cpu.next = mipsWord(0x88000000), mipsWord(0x88000004)
	m.cpu.cp0[status] = 1 | 1<<10
	m.scc.ports[0].wr[9] = 8
	m.scc.ports[ip24SerialPort].wr[3] = 1
	m.scc.ports[ip24SerialPort].wr[1] = 8
	m.int3.reg[5], m.int3.reg[1] = 1<<5, 1<<7
	binary.BigEndian.PutUint32(m.ram, 0x1000ffff)
	if stop, err := m.run(t.Context(), 8192, 1); err != nil || stop.Kind != "budget" {
		t.Fatalf("serial was idle: %+v %v", stop, err)
	}
	if _, err := m.console.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	stop, err := m.run(t.Context(), 8192, 1)
	if err != nil || stop.Kind != "exception" || stop.Exception != 0 || stop.Cycles != 1 || m.scc.ports[ip24SerialPort].rx != 'x' {
		t.Fatalf("serial did not wake next instruction: %+v %v", stop, err)
	}
}
