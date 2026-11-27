package s390

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/tinyrange/trex/filesystem/ckd"
)

// Machine checkpoints. A checkpoint holds the mutable state of a machine:
// storage and keys, the CPUs, the channel subsystem with any channel
// programs waiting at a CCW, the service processor, and every device's
// state, including the tracks written to each DASD's overlay. Media are
// not included: a checkpoint is restored into a machine configured the same
// way (same storage size, CPUs, devices and media), and each DASD records a
// fingerprint of its base volume so a checkpoint is never applied to
// different media.
//
// The format is the magic below followed by a raw DEFLATE stream of one gob
// value (machineSnap).

var snapshotMagic = []byte("TREXS390\x00\x01")

type machineSnap struct {
	NoIntervalTimer                         bool
	S370                                    bool
	S360, Model9020, Model50, Model65, IOCE bool
	Model9020A                              bool
	Model9020E                              bool
	MemSize                                 int
	MainEnd9020E                            uint32
	ByteMuxSubchannels                      int
	KeyShift                                uint
	TOD, LastStck                           uint64
	TODProgrammable                         uint16
	ServiceSignal                           bool
	ServiceParam                            uint32
	InputWake                               bool
	LoadParm                                string
	SCPConfig                               [6]byte
	Facilities                              uint32
	SCPCPUFacilities                        [12]byte
	SCLP                                    sclpSnap
	CPUs                                    []cpuSnap
	Subchannels                             []subSnap
	CRW                                     []uint32
	CRWPend                                 bool
	Devices                                 []devSnap
	Mem, Keys                               []byte
	MACH                                    []byte
	IOCEATR                                 [3]channelATR9020
	IOCEChecks9020                          [3]ioceMachineCheck9020
	StorageLogout9020                       [max9020StorageElements]storageLogout9020
	StorageLatches9020                      [max9020StorageElements][2]storageCycle9020
	Storage9020A                            [max9020AStorageElements]storageElement9020A
	StorageBadParity9020                    map[uint32]byte
	StorageBadKey9020                       map[uint32]bool
	Configuration9020                       [32]configRegister9020
	DisplayRefresh9020E                     [max9020EDisplayElements]displayRefresh9020E
	RCUEndpoints9020                        [28]rcuEndpoint9020
}

type sclpSnap struct {
	CPReceive, CPSend uint32
	Pending           []sclpEventSnap
	Lines             []string
	Partial           []byte
	Dropped           int
	Version           uint64
}

type sclpEventSnap struct {
	Type byte
	Data []byte
}

type cpuSnap struct {
	Addr                             uint16
	GR, AR, CR                       [16]uint32
	FPR                              [16]uint64
	FPC                              uint32
	PSW                              PSW
	Prefix                           uint32
	ClockComparator                  uint64
	Amask, PgMask                    uint32
	ITBase, ITDone                   uint64
	ITPending                        bool
	Stopped, Check                   bool
	CheckReason                      string
	ExtPending                       uint32
	Emergency                        uint64
	ExtCallFrom                      uint16
	TimerValue                       int64
	TimerRef                         uint64
	Instructions                     uint64
	SIEEntries                       uint64
	DXC                              byte
	IODelay                          int
	ExcAddr, ExcSpace                uint32
	DAR9020, DARMask9020, Checks9020 uint32
	MachineCheck9020                 machineCheck9020
	PIR9020                          byte
	ATR9020                          uint64
	ATRSet9020                       bool
	PSB9020                          uint32
	PSBAlternate9020                 bool
	Local9020                        [4][16]uint32
	Delay9020                        uint64
	DiagnosticSE1                    bool
	Interleave9020                   interleave9020
	InterleavePanel9020              interleave9020
	TimerInhibitSince9020            uint64
	CountLogoutAt9020                uint64
	ReverseSumParity9020             bool
	ReverseMarkParity9020            bool
	ReverseAddressParity9020         storageCycleFlags9020
	ScanPrefetch9020                 scanPrefetch9020
	DisplayWrap9020E                 byte
	SIE                              *sieSnap // interpretive execution in progress
}

// sieSnap is the host state saved by START INTERPRETIVE EXECUTION; the
// guest's translation cache is rebuilt after a restore.
type sieSnap struct {
	SD, SIEIA          uint32
	Host               PSW
	HostCR             [16]uint32
	HostPrefix         uint32
	HostGR14, HostGR15 uint32
	HostTimerValue     int64
	HostTimerRef       uint64
	HostCKC            uint64
	HostSTD, HostCR0   uint32
	MSO, MSE           uint32
	VR                 bool
	M, MX              byte
	IC, EC             [4]byte
	LCTL               uint16
	SVC                [4]byte
	CPUAD              uint16
	Epoch              uint64
}

func (s *sieState) snap() *sieSnap {
	return &sieSnap{SD: s.sd, SIEIA: s.sieIA, Host: s.host, HostCR: s.hostCR, HostPrefix: s.hostPrefix,
		HostGR14: s.hostGR14, HostGR15: s.hostGR15, HostTimerValue: s.hostTimerValue, HostTimerRef: s.hostTimerRef,
		HostCKC: s.hostCKC, HostSTD: s.hostSTD, HostCR0: s.hostCR0, MSO: s.mso, MSE: s.mse, VR: s.vr, M: s.m, MX: s.mx,
		IC: s.ic, EC: s.ec, LCTL: s.lctl, SVC: s.svc, CPUAD: s.cpuad, Epoch: s.epoch}
}

func (s *sieSnap) state() *sieState {
	return &sieState{sd: s.SD, sieIA: s.SIEIA, host: s.Host, hostCR: s.HostCR, hostPrefix: s.HostPrefix,
		hostGR14: s.HostGR14, hostGR15: s.HostGR15, hostTimerValue: s.HostTimerValue, hostTimerRef: s.HostTimerRef,
		hostCKC: s.HostCKC, hostSTD: s.HostSTD, hostCR0: s.HostCR0, mso: s.MSO, mse: s.MSE, vr: s.VR, m: s.M, mx: s.MX,
		ic: s.IC, ec: s.EC, lctl: s.LCTL, svc: s.SVC, cpuad: s.CPUAD, epoch: s.Epoch}
}

type subSnap struct {
	Num, Devno                       uint16
	CE9020                           uint16
	Intparm                          uint32
	ISC                              byte
	Enabled                          bool
	LPM                              byte
	MBI                              uint16
	MM, Limit                        byte
	Multipath, Timing                bool
	Key, CCWFmt                      byte
	Flags                            uint32
	FC, AC, SC                       byte
	CCWAddr                          uint32
	DevStatus, SchStatus             byte
	Residual                         uint16
	Pending, IRQ                     bool
	CCDeferred                       byte
	Sense                            []byte
	HeldStatus                       byte
	AttnHold                         bool // legacy checkpoints stored only attention
	Blocked                          bool
	BlockAddr                        uint32
	BlockFmt1, PCIWait, PCIInterrupt bool
	PCIAt                            uint64
	Timed, DevPending                bool
	EndCE, EndDE                     uint64
	CCWs                             int
	ResumeAt, FinishAt, DEAt         uint64
	CUBusyUntil                      uint64
	CUEndWanted                      bool
	DEStatus                         byte
	EndAtDE                          bool
	Op                               *opSnap
}

// opSnap is a CCW whose data transfer is in progress (ccwOp).
type opSnap struct {
	Cmd                 byte
	Chain               []ccwSnap // the last element is the CCW that ends the transfer
	Addrs               []uint32
	Segs                []segSnap
	Total, Cur          uint32
	ReadStored          uint32
	OutputFetched       uint32
	InputLimit          uint32
	Out                 []byte
	TapeWrite           []byte
	DiskWrite           *diskWrite2314
	RKMOrder            byte
	RKMOutput           []byte
	RKMOperator         rkmOperator9020E
	TimedOutput         bool
	OutputOverrun       bool
	Used                int
	Status              byte
	Read, Chained, Fmt1 bool
	Halted              bool
	LengthOnException   bool
	Key, Err            byte
	ChainErr            uint32
	ChainStatus         byte
	Checked             bool
}

type ccwSnap struct {
	Cmd, Flags byte
	Count      uint16
	Addr       uint32
}

type segSnap struct {
	Addr, N uint32
	Skip    bool
}

func snapOp(op *ccwOp) *opSnap {
	if op == nil {
		return nil
	}
	o := &opSnap{Cmd: op.Cmd, Addrs: op.Addrs, Total: op.Total, Cur: op.Cur, ReadStored: op.ReadStored, OutputFetched: op.OutputFetched, InputLimit: op.InputLimit, Out: op.Out, TapeWrite: op.TapeWrite, DiskWrite: op.DiskWrite, TimedOutput: op.TimedOutput, Used: op.Used, Halted: op.Halted,
		Status: op.Status, Read: op.Read, Chained: op.Chained, Fmt1: op.Fmt1, Key: op.Key, Err: op.Err, ChainErr: op.ChainErr, ChainStatus: op.ChainStatus, Checked: op.Checked,
		LengthOnException: op.LengthOnException, OutputOverrun: op.OutputOverrun,
		RKMOrder: op.RKMOrder, RKMOutput: op.RKMOutput, RKMOperator: op.RKMOperator}
	for _, w := range append(append([]ccw(nil), op.Chain...), op.Last) {
		o.Chain = append(o.Chain, ccwSnap{w.cmd, w.flags, w.count, w.addr})
	}
	for _, g := range op.Segs {
		o.Segs = append(o.Segs, segSnap{g.addr, g.n, g.skip})
	}
	return o
}

func (o *opSnap) op() *ccwOp {
	if o == nil {
		return nil
	}
	op := &ccwOp{Cmd: o.Cmd, Addrs: o.Addrs, Total: o.Total, Cur: o.Cur, ReadStored: o.ReadStored, OutputFetched: o.OutputFetched, InputLimit: o.InputLimit, Out: o.Out, TapeWrite: o.TapeWrite, DiskWrite: o.DiskWrite, TimedOutput: o.TimedOutput, Used: o.Used, Halted: o.Halted,
		Status: o.Status, Read: o.Read, Chained: o.Chained, Fmt1: o.Fmt1, Key: o.Key, Err: o.Err, ChainErr: o.ChainErr, ChainStatus: o.ChainStatus, Checked: o.Checked,
		LengthOnException: o.LengthOnException, OutputOverrun: o.OutputOverrun,
		RKMOrder: o.RKMOrder, RKMOutput: o.RKMOutput, RKMOperator: o.RKMOperator}
	for _, w := range o.Chain {
		op.Chain = append(op.Chain, ccw{w.Cmd, w.Flags, w.Count, w.Addr})
	}
	op.Last = op.Chain[len(op.Chain)-1]
	op.Chain = op.Chain[:len(op.Chain)-1]
	for _, g := range o.Segs {
		op.Segs = append(op.Segs, segment{g.Addr, g.N, g.Skip})
	}
	return op
}

type devSnap struct {
	Devno          uint16
	Kind           string
	Data           []byte
	Controller9020 uint8
}

// snapshotter is implemented by devices whose state can be checkpointed.
type snapshotter interface {
	snapshotKind() string
	snapshot() ([]byte, error)
	restore(data []byte, disksOnly bool) error
}

func encodeGob(v any) ([]byte, error) {
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(v)
	return b.Bytes(), err
}

func decodeGob(data []byte, v any) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(v)
}

// capture copies the machine's mutable state. Storage is copied, so the
// result stays valid while the machine continues to run.
func (m *Machine) capture() (*machineSnap, error) {
	s := &machineSnap{NoIntervalTimer: m.cfg.NoIntervalTimer, S370: m.S370, S360: m.S360, Model9020: m.Model9020, Model50: m.cfg.Model50, Model65: m.cfg.Model65, IOCE: m.cfg.IOCE, MemSize: len(m.S.Mem), KeyShift: m.S.KeyShift,
		ByteMuxSubchannels: m.cfg.ByteMuxSubchannels,
		MainEnd9020E:       m.S.mainEnd9020E,
		TOD:                m.tod, LastStck: m.lastStck, TODProgrammable: m.todProgrammable,
		ServiceSignal: m.serviceSignal, ServiceParam: m.serviceParam, InputWake: m.inputWake,
		LoadParm: m.LoadParm, SCPConfig: m.SCPConfig, Facilities: m.Facilities, SCPCPUFacilities: m.SCPCPUFacilities,
		CRW: append([]uint32(nil), m.CSS.crw...), CRWPend: m.CSS.crwPend,
		Mem: append([]byte(nil), m.S.Mem...), Keys: append([]byte(nil), m.S.Keys...),
		MACH: append([]byte(nil), m.CSS.mach...), IOCEATR: m.CSS.ioceATR, IOCEChecks9020: m.CSS.ioceChecks9020, StorageLogout9020: m.storageLogout9020,
		StorageLatches9020: m.storageLatches9020, StorageBadParity9020: maps.Clone(m.storageBadParity9020),
		StorageBadKey9020: maps.Clone(m.storageBadKey9020),
		Model9020A:        m.cfg.Model9020A, Model9020E: m.cfg.Model9020E, Storage9020A: m.storage9020A, Configuration9020: m.configuration9020,
		DisplayRefresh9020E: m.displayRefresh9020E, RCUEndpoints9020: m.CSS.rcuEndpoints9020}
	for i := range s.RCUEndpoints9020 {
		rkm := &s.RCUEndpoints9020[i].RKM
		rkm.Input = slices.Clone(rkm.Input)
		if rkm.Memory != nil {
			memory := *rkm.Memory
			rkm.Memory = &memory
		}
	}
	sc := m.sclp
	s.SCLP = sclpSnap{CPReceive: sc.cpReceive, CPSend: sc.cpSend, Lines: append([]string(nil), sc.Lines...),
		Partial: append([]byte(nil), sc.Partial...), Dropped: sc.dropped, Version: sc.version}
	for _, e := range sc.pending {
		s.SCLP.Pending = append(s.SCLP.Pending, sclpEventSnap{e.typ, append([]byte(nil), e.data...)})
	}
	for _, c := range m.CPUs {
		var sie *sieSnap
		if c.sie != nil {
			sie = c.sie.snap()
		}
		s.CPUs = append(s.CPUs, cpuSnap{SIE: sie, Addr: c.Addr, GR: c.GR, AR: c.AR, CR: c.CR, FPR: c.FPR, FPC: c.FPC,
			PSW: c.PSW, Prefix: c.Prefix, ClockComparator: c.ClockComparator, Amask: c.amask, PgMask: c.pgMask,
			ITBase: c.itBase, ITDone: c.itDone, ITPending: c.itPending, Stopped: c.Stopped, Check: c.Check,
			CheckReason: c.checkReason, ExtPending: c.extPending, Emergency: c.emergency, ExtCallFrom: c.extCallFrom,
			TimerValue: c.timerValue, TimerRef: c.timerRef, Instructions: c.Instructions, SIEEntries: c.SIEEntries,
			DXC: c.dxc, ExcAddr: c.excAddr, ExcSpace: c.excSpace, IODelay: c.ioDelay,
			DAR9020: c.maintenance9020.dar, DARMask9020: c.maintenance9020.darMask,
			Checks9020: c.maintenance9020.checks, PIR9020: c.maintenance9020.pir,
			MachineCheck9020: c.maintenance9020.machineCheck,
			ATR9020:          c.maintenance9020.atr, ATRSet9020: c.maintenance9020.atrSet, PSB9020: c.maintenance9020.psb, PSBAlternate9020: c.maintenance9020.psbAlternate,
			Local9020: c.maintenance9020.local, Delay9020: c.maintenance9020.delayUntil, DiagnosticSE1: c.maintenance9020.diagnosticSE1,
			Interleave9020: c.maintenance9020.interleave, InterleavePanel9020: c.interleavePanel9020,
			TimerInhibitSince9020: c.maintenance9020.timerInhibitSince,
			ReverseSumParity9020:  c.maintenance9020.reverseSumParity,
			CountLogoutAt9020:     c.maintenance9020.countLogoutAt, ReverseMarkParity9020: c.maintenance9020.reverseMarkParity,
			ReverseAddressParity9020: c.maintenance9020.reverseAddressParity, ScanPrefetch9020: c.maintenance9020.scanPrefetch,
			DisplayWrap9020E: c.maintenance9020.displayWrap})
	}
	for _, x := range m.CSS.subs {
		s.Subchannels = append(s.Subchannels, subSnap{Num: x.num, Devno: x.devno, CE9020: x.ce9020, Intparm: x.intparm, ISC: x.isc,
			Enabled: x.enabled, LPM: x.lpm, MBI: x.mbi, MM: x.mm, Limit: x.limit, Multipath: x.multip, Timing: x.timing,
			Key: x.key, CCWFmt: x.ccwfmt, Flags: x.flags, FC: x.fc, AC: x.ac, SC: x.sc, CCWAddr: x.ccwaddr,
			DevStatus: x.devStatus, SchStatus: x.schStatus, Residual: x.residual, Pending: x.pending, IRQ: x.irq,
			CCDeferred: x.ccDeferred, Sense: append([]byte(nil), x.sense...), HeldStatus: x.heldStatus,
			Blocked: x.blocked, BlockAddr: x.blockAddr, BlockFmt1: x.blockFmt1, PCIWait: x.pciWait,
			PCIInterrupt: x.pciIRQ, PCIAt: x.pciAt, Timed: x.timed, DevPending: x.devPending, EndCE: x.endCE, EndDE: x.endDE,
			CCWs: x.ccws, ResumeAt: x.resumeAt, FinishAt: x.finishAt, DEAt: x.deAt, DEStatus: x.deStatus,
			CUBusyUntil: x.cuBusyUntil, CUEndWanted: x.cuEndWanted, EndAtDE: x.endAtDE, Op: snapOp(x.op)})
		sn, ok := x.dev.(snapshotter)
		if !ok {
			return nil, fmt.Errorf("s390: device %04X (%T) cannot be checkpointed", x.devno, x.dev)
		}
		data, err := sn.snapshot()
		if err != nil {
			return nil, fmt.Errorf("s390: device %04X: %w", x.devno, err)
		}
		s.Devices = append(s.Devices, devSnap{Devno: x.devno, Kind: sn.snapshotKind(), Data: data, Controller9020: x.controller9020})
	}
	return s, nil
}

// writeSnapshot encodes a captured state as a checkpoint.
func writeSnapshot(w io.Writer, s *machineSnap) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	if _, err := bw.Write(snapshotMagic); err != nil {
		return err
	}
	fw, err := flate.NewWriter(bw, flate.BestSpeed)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(fw).Encode(s); err != nil {
		return err
	}
	if err := fw.Close(); err != nil {
		return err
	}
	return bw.Flush()
}

// Save writes a checkpoint of the machine to w. It must not run
// concurrently with Run.
func (m *Machine) Save(w io.Writer) error {
	s, err := m.capture()
	if err != nil {
		return err
	}
	return writeSnapshot(w, s)
}

// Restore loads a checkpoint written by Save into m, which must be
// configured as the saved machine was: same architecture, storage size,
// CPUs and devices on the same media. With disksOnly only the DASDs'
// written tracks are restored, as for a fresh IPL of a system whose disks
// persist; the machine is otherwise left as configured.
func (m *Machine) Restore(r io.Reader, disksOnly bool) error {
	br := bufio.NewReaderSize(r, 1<<20)
	magic := make([]byte, len(snapshotMagic))
	if _, err := io.ReadFull(br, magic); err != nil || !bytes.Equal(magic, snapshotMagic) {
		return errors.New("s390: not a machine checkpoint")
	}
	var s machineSnap
	if err := gob.NewDecoder(flate.NewReader(br)).Decode(&s); err != nil {
		return fmt.Errorf("s390: checkpoint: %w", err)
	}
	// Validate everything before changing anything.
	if s.NoIntervalTimer != m.cfg.NoIntervalTimer || s.S370 != m.S370 || s.S360 != m.S360 || s.Model9020 != m.Model9020 ||
		s.Model9020A != m.cfg.Model9020A || s.Model9020E != m.cfg.Model9020E || s.Model50 != m.cfg.Model50 || s.Model65 != m.cfg.Model65 ||
		s.IOCE != m.cfg.IOCE || s.ByteMuxSubchannels != m.cfg.ByteMuxSubchannels || s.MemSize != len(m.S.Mem) ||
		s.MainEnd9020E != m.S.mainEnd9020E || len(s.CPUs) != len(m.CPUs) {
		return fmt.Errorf("s390: checkpoint is of a different machine (%d bytes, %d CPUs, S/370 %v)", s.MemSize, len(s.CPUs), s.S370)
	}
	if len(s.MACH) != 0 && len(s.MACH) != len(m.CSS.mach) {
		return fmt.Errorf("s390: checkpoint has %d bytes of MACH storage, the machine %d", len(s.MACH), len(m.CSS.mach))
	}
	devs := map[uint16]devSnap{}
	for _, d := range s.Devices {
		devs[d.Devno] = d
	}
	// A disks-only restore needs the same DASDs; other devices may differ,
	// as when a network adapter is added between boots.
	machineDevs := len(m.CSS.subs)
	if disksOnly {
		machineDevs = 0
		for _, x := range m.CSS.subs {
			if _, isDASD := x.dev.(*DASD3390); isDASD {
				machineDevs++
			}
		}
		for n, d := range devs {
			if !strings.HasPrefix(d.Kind, "dasd-") {
				delete(devs, n)
			}
		}
	}
	if len(devs) != machineDevs {
		return fmt.Errorf("s390: checkpoint has %d devices, the machine %d", len(devs), machineDevs)
	}
	for _, x := range m.CSS.subs {
		if _, isDASD := x.dev.(*DASD3390); disksOnly && !isDASD {
			continue
		}
		d, ok := devs[x.devno]
		sn, can := x.dev.(snapshotter)
		if !ok || !can || sn.snapshotKind() != d.Kind || x.controller9020 != d.Controller9020 {
			return fmt.Errorf("s390: device %04X differs from the checkpoint", x.devno)
		}
		if dasd, isDASD := x.dev.(*DASD3390); isDASD {
			if err := dasd.checkFingerprint(d.Data); err != nil {
				return fmt.Errorf("s390: device %04X: %w", x.devno, err)
			}
		}
	}
	for _, x := range m.CSS.subs {
		if _, isDASD := x.dev.(*DASD3390); disksOnly && !isDASD {
			continue
		}
		if err := x.dev.(snapshotter).restore(devs[x.devno].Data, disksOnly); err != nil {
			return fmt.Errorf("s390: device %04X: %w", x.devno, err)
		}
	}
	if disksOnly {
		// The disks hold times from the saved run, which an operating
		// system may refuse as being in the future, so the machine is
		// powered on after it was saved rather than at its configured start.
		if s.TOD >= m.tod {
			m.tod = s.TOD + 60_000_000*todMicro
		}
		return nil
	}
	copy(m.S.Mem, s.Mem)
	copy(m.S.Keys, s.Keys)
	clear(m.CSS.mach)
	copy(m.CSS.mach, s.MACH)
	m.CSS.ioceATR = s.IOCEATR
	m.CSS.ioceChecks9020 = s.IOCEChecks9020
	m.storageLogout9020 = s.StorageLogout9020
	m.storageLatches9020 = s.StorageLatches9020
	m.storage9020A = s.Storage9020A
	m.storageBadParity9020 = maps.Clone(s.StorageBadParity9020)
	m.storageBadKey9020 = maps.Clone(s.StorageBadKey9020)
	m.configuration9020 = s.Configuration9020
	m.displayRefresh9020E = s.DisplayRefresh9020E
	m.CSS.rcuEndpoints9020 = s.RCUEndpoints9020
	m.tod, m.lastStck, m.todProgrammable = s.TOD, s.LastStck, s.TODProgrammable
	for i := range m.cfg.DisplayElements9020E {
		d := &m.displayRefresh9020E[i]
		if d.DGMask != 0 && d.Tails == [4]byte{} {
			// Older snapshots scheduled one event per full sweep.
			d.NextScan = 0
			m.configureDisplay9020E(i, d.DGMask)
		}
	}
	m.updateDisplayDeadline9020E()
	m.serviceSignal, m.serviceParam, m.inputWake = s.ServiceSignal, s.ServiceParam, s.InputWake
	m.LoadParm, m.SCPConfig, m.Facilities, m.SCPCPUFacilities = s.LoadParm, s.SCPConfig, s.Facilities, s.SCPCPUFacilities
	m.keyGen++
	sc := m.sclp
	sc.cpReceive, sc.cpSend = s.SCLP.CPReceive, s.SCLP.CPSend
	sc.Lines, sc.Partial, sc.dropped, sc.version = s.SCLP.Lines, s.SCLP.Partial, s.SCLP.Dropped, s.SCLP.Version+1
	sc.pending = nil
	for _, e := range s.SCLP.Pending {
		sc.pending = append(sc.pending, sclpEvent{e.Type, e.Data})
	}
	for i, cs := range s.CPUs {
		c := m.CPUs[i]
		c.Addr, c.GR, c.AR, c.CR, c.FPR, c.FPC = cs.Addr, cs.GR, cs.AR, cs.CR, cs.FPR, cs.FPC
		c.PSW, c.Prefix, c.ClockComparator = cs.PSW, cs.Prefix, cs.ClockComparator
		c.amask, c.pgMask = cs.Amask, cs.PgMask
		c.itBase, c.itDone, c.itPending = cs.ITBase, cs.ITDone, cs.ITPending
		c.Stopped, c.Check, c.checkReason = cs.Stopped, cs.Check, cs.CheckReason
		c.extPending, c.emergency, c.extCallFrom = cs.ExtPending, cs.Emergency, cs.ExtCallFrom
		c.timerValue, c.timerRef = cs.TimerValue, cs.TimerRef
		c.Instructions, c.SIEEntries, c.dxc, c.ioDelay = cs.Instructions, cs.SIEEntries, cs.DXC, cs.IODelay
		c.excAddr, c.excSpace = cs.ExcAddr, cs.ExcSpace
		c.maintenance9020 = maintenance9020{dar: cs.DAR9020, darMask: cs.DARMask9020, checks: cs.Checks9020, pir: cs.PIR9020,
			atr: cs.ATR9020, atrSet: cs.ATRSet9020, psb: cs.PSB9020, psbAlternate: cs.PSBAlternate9020, local: cs.Local9020,
			delayUntil: cs.Delay9020, diagnosticSE1: cs.DiagnosticSE1, machineCheck: cs.MachineCheck9020,
			interleave: cs.Interleave9020, timerInhibitSince: cs.TimerInhibitSince9020, countLogoutAt: cs.CountLogoutAt9020,
			reverseSumParity:  cs.ReverseSumParity9020,
			reverseMarkParity: cs.ReverseMarkParity9020, reverseAddressParity: cs.ReverseAddressParity9020,
			scanPrefetch: cs.ScanPrefetch9020, displayWrap: cs.DisplayWrap9020E}
		c.interleavePanel9020 = cs.InterleavePanel9020
		c.next = c.PSW.IA
		c.sie = nil
		if cs.SIE != nil {
			c.sie = cs.SIE.state() // its translation cache starts empty
		}
		c.purgeTLB()
		c.ipageValid = false
		c.pswChanged = true
		c.quiet = 0
	}
	byNum := map[uint16]subSnap{}
	for _, x := range s.Subchannels {
		byNum[x.Devno] = x
	}
	for _, x := range m.CSS.subs {
		ss := byNum[x.devno]
		x.ce9020 = ss.CE9020
		x.intparm, x.isc, x.enabled, x.lpm, x.mbi = ss.Intparm, ss.ISC, ss.Enabled, ss.LPM, ss.MBI
		x.mm, x.limit, x.multip, x.timing = ss.MM, ss.Limit, ss.Multipath, ss.Timing
		x.key, x.ccwfmt, x.flags, x.fc, x.ac, x.sc = ss.Key, ss.CCWFmt, ss.Flags, ss.FC, ss.AC, ss.SC
		x.ccwaddr, x.devStatus, x.schStatus, x.residual = ss.CCWAddr, ss.DevStatus, ss.SchStatus, ss.Residual
		x.pending, x.irq, x.ccDeferred, x.sense, x.heldStatus = ss.Pending, ss.IRQ, ss.CCDeferred, ss.Sense, ss.HeldStatus
		if ss.AttnHold {
			x.heldStatus |= usAttention
		}
		x.blocked, x.blockAddr, x.blockFmt1 = ss.Blocked, ss.BlockAddr, ss.BlockFmt1
		x.pciWait, x.pciIRQ, x.pciAt = ss.PCIWait, ss.PCIInterrupt, ss.PCIAt
		x.timed, x.devPending, x.endCE, x.endDE, x.ccws = ss.Timed, ss.DevPending, ss.EndCE, ss.EndDE, ss.CCWs
		x.resumeAt, x.finishAt, x.deAt, x.deStatus, x.endAtDE = ss.ResumeAt, ss.FinishAt, ss.DEAt, ss.DEStatus, ss.EndAtDE
		x.cuBusyUntil, x.cuEndWanted = ss.CUBusyUntil, ss.CUEndWanted
		x.op = ss.Op.op()
	}
	m.CSS.crw, m.CSS.crwPend = s.CRW, s.CRWPend
	m.CSS.reschedule()
	return nil
}

// --- devices ---------------------------------------------------------------

type dasdSnap struct {
	Fingerprint                   []byte
	Overlay                       map[uint32][]ckd.Record
	Home                          map[uint32][5]byte
	Overflow                      map[uint32]map[int]bool
	R0Checks                      map[uint32]int
	Cyl, Head                     uint32
	Rec                           int
	AfterData, AfterKey           bool
	SeekIncomplete                bool
	PlugRemoved                   bool
	MotorStopped                  bool
	Physical2314                  uint16
	SeekExtra2314                 time.Duration
	IndexPass                     int
	Extent                        bool
	Mask                          byte
	MaskSet                       bool
	ExtBeg, ExtEnd                uint32
	Locate                        bool
	LROp                          byte
	LRCount                       int
	LROrient                      byte
	LRSearch                      [5]byte
	LRSearched, LRFirst           bool
	Sense                         [32]byte
	RSSD                          byte
	Reserved                      bool
	PGID                          [11]byte
	Chained                       bool
	PrevCmd                       byte
	SearchMatch                   byte
	SpaceLengths                  [3]byte
	Cylinders, Heads              uint32
	DevType                       uint16
	OverlayTracks, OverlayRecords int
}

// fingerprint identifies the base volume: geometry, type and a hash of
// its first track.
func (d *DASD3390) fingerprint() ([]byte, error) {
	h := sha256.New()
	fmt.Fprintf(h, "%04X/%d/%d", d.devType, d.cylinders, d.heads)
	recs, err := d.base.Track(0)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		fmt.Fprintf(h, "|%d/%d/%d/%d/%d", r.Cylinder, r.Head, r.Number, len(r.Key), len(r.Data))
		h.Write(r.Key)
		h.Write(r.Data)
	}
	return h.Sum(nil), nil
}

func (d *DASD3390) snapshotKind() string { return fmt.Sprintf("dasd-%04X", d.devType) }

func (d *DASD3390) snapshot() ([]byte, error) {
	fp, err := d.fingerprint()
	if err != nil {
		return nil, err
	}
	// Copy the overlay: its records may be updated in place later.
	overlay := make(map[uint32][]ckd.Record, len(d.overlay))
	for t, recs := range d.overlay {
		cp := make([]ckd.Record, len(recs))
		for i, r := range recs {
			cp[i] = ckd.Record{Cylinder: r.Cylinder, Head: r.Head, Number: r.Number,
				Key: append([]byte(nil), r.Key...), Data: append([]byte(nil), r.Data...)}
		}
		overlay[t] = cp
	}
	return encodeGob(dasdSnap{Fingerprint: fp, Overlay: overlay, Home: d.home, Overflow: d.overflow, R0Checks: d.r0Checks, Cyl: d.cyl, Head: d.head, Rec: d.rec,
		AfterData: d.afterData, AfterKey: d.afterKey, SeekIncomplete: d.seekIncomplete, PlugRemoved: d.plugRemoved,
		MotorStopped:  d.motorStopped,
		Physical2314:  d.physical2314,
		SeekExtra2314: d.seekExtra2314,
		IndexPass:     d.indexPass, Extent: d.extent, Mask: d.mask, MaskSet: d.maskSet,
		ExtBeg: d.extBeg, ExtEnd: d.extEnd, Locate: d.locate, LROp: d.lrOp, LRCount: d.lrCount, LROrient: d.lrOrient,
		LRSearch: d.lrSearch, LRSearched: d.lrSearched, LRFirst: d.lrFirst, Sense: d.sense, RSSD: d.rssd,
		Reserved: d.reserved, PGID: d.pgid, Chained: d.chained, PrevCmd: d.prevCmd, SearchMatch: d.searchMatch, SpaceLengths: d.spaceLengths,
		Cylinders: d.cylinders, Heads: d.heads, DevType: d.devType})
}

func (d *DASD3390) checkFingerprint(data []byte) error {
	var s dasdSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	fp, err := d.fingerprint()
	if err != nil {
		return err
	}
	if !bytes.Equal(fp, s.Fingerprint) {
		return errors.New("the checkpoint was taken with a different volume")
	}
	return nil
}

func (d *DASD3390) restore(data []byte, disksOnly bool) error {
	var s dasdSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	d.overlay = s.Overlay
	d.home = s.Home
	d.overflow = s.Overflow
	if d.overlay == nil {
		d.overlay = map[uint32][]ckd.Record{}
	}
	if disksOnly {
		return nil
	}
	d.r0Checks = s.R0Checks
	d.cyl, d.head, d.rec, d.afterData, d.afterKey, d.indexPass = s.Cyl, s.Head, s.Rec, s.AfterData, s.AfterKey, s.IndexPass
	d.seekIncomplete = s.SeekIncomplete
	d.plugRemoved = s.PlugRemoved
	d.motorStopped = s.MotorStopped
	d.physical2314 = s.Physical2314
	d.seekExtra2314 = s.SeekExtra2314
	if d.physical2314 == 0 && d.devType == 0x2314 {
		d.physical2314 = d.devno + 1
	}
	d.extent, d.mask, d.maskSet, d.extBeg, d.extEnd = s.Extent, s.Mask, s.MaskSet, s.ExtBeg, s.ExtEnd
	d.locate, d.lrOp, d.lrCount, d.lrOrient, d.lrSearch, d.lrSearched, d.lrFirst = s.Locate, s.LROp, s.LRCount, s.LROrient, s.LRSearch, s.LRSearched, s.LRFirst
	d.sense, d.rssd, d.reserved, d.pgid, d.chained, d.prevCmd = s.Sense, s.RSSD, s.Reserved, s.PGID, s.Chained, s.PrevCmd
	d.searchMatch = s.SearchMatch
	d.spaceLengths = s.SpaceLengths
	return nil
}

// OverlayTracks returns the number of tracks written since the volume was
// attached (or restored).
func (d *DASD3390) OverlayTracks() int { return len(d.overlay) }

type console3270Snap struct {
	Rows, Cols                   int
	Buf                          []byte
	FA                           []bool
	Color, Hilite                []byte
	Cursor                       int
	AID, Sense                   byte
	Writes, Edits                uint64
	Locked, Insert, QueryPending bool
	BufAddr                      int
	DefRows, DefCols             int
	AltRows, AltCols             int
	Alt                          bool
}

func (t *Console3270) snapshotKind() string { return "3270" }

func (t *Console3270) snapshot() ([]byte, error) {
	return encodeGob(console3270Snap{Rows: t.Rows, Cols: t.Cols, Buf: t.buf, FA: t.fa, Color: t.color, Hilite: t.hilite,
		Cursor: t.cursor, AID: t.aid, Sense: t.sense, Writes: t.Writes, Edits: t.edits, Locked: t.locked,
		Insert: t.insert, QueryPending: t.queryPending, BufAddr: t.bufAddr,
		DefRows: t.defRows, DefCols: t.defCols, AltRows: t.altRows, AltCols: t.altCols, Alt: t.alt})
}

func (t *Console3270) restore(data []byte, _ bool) error {
	var s console3270Snap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	if s.DefRows == 0 { // written before alternate sizes were kept
		s.DefRows, s.DefCols, s.AltRows, s.AltCols = s.Rows, s.Cols, s.Rows, s.Cols
	}
	if s.DefRows != t.defRows || s.DefCols != t.defCols {
		return fmt.Errorf("3270 size %dx%d, checkpoint %dx%d", t.defRows, t.defCols, s.DefRows, s.DefCols)
	}
	t.altRows, t.altCols, t.alt, t.Rows, t.Cols = s.AltRows, s.AltCols, s.Alt, s.Rows, s.Cols
	n := t.size()
	fill := func(b []byte) []byte { return append(b, make([]byte, n-len(b))...)[:n] }
	t.buf, t.color, t.hilite = fill(s.Buf), fill(s.Color), fill(s.Hilite)
	t.fa = append(s.FA, make([]bool, n-len(s.FA))...)[:n]
	t.cursor, t.aid, t.sense = s.Cursor, s.AID, s.Sense
	// Versions only increase, so viewers notice the restored screen.
	t.Writes, t.edits = max(t.Writes, s.Writes)+1, max(t.edits, s.Edits)
	t.locked, t.insert, t.queryPending, t.bufAddr = s.Locked, s.Insert, s.QueryPending, s.BufAddr
	for _, f := range t.observers {
		f(t.DataStream(true))
	}
	return nil
}

type console3215Snap struct {
	Lines                          []string
	Partial                        string
	Input                          []string
	Sense                          byte
	Dropped                        int
	Version                        uint64
	NotReady, ReadyEnd, CancelRead bool
	ReadStatus                     byte
	WriteLines                     int
	CarrierColumn, WriteColumn     int
	HasCarrierColumn               bool
	RibbonShift                    bool
	Ribbon, WriteRibbon            ribbon1052
	WritePartial                   string
	WriteData                      []byte
	WriteReturn                    bool
}

func (t *Console3215) snapshotKind() string { return "3215" }

func (t *Console3215) snapshot() ([]byte, error) {
	return encodeGob(t.consoleState())
}

func (t *Console3215) consoleState() console3215Snap {
	return console3215Snap{Lines: t.Lines, Partial: t.Partial, Input: t.input, Sense: t.sense,
		Dropped: t.dropped, Version: t.version}
}

func (t *Console3215) restore(data []byte, _ bool) error {
	var s console3215Snap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	t.restoreConsoleState(s)
	return nil
}

func (t *Console3215) restoreConsoleState(s console3215Snap) {
	t.Lines, t.Partial, t.input, t.sense, t.dropped = s.Lines, s.Partial, s.Input, s.Sense, s.Dropped
	t.version = max(t.version, s.Version) + 1
}

func (t *Console1052) snapshot() ([]byte, error) {
	s := t.consoleState()
	s.NotReady, s.ReadyEnd, s.ReadStatus = t.notReady, t.readyEnd, t.readStatus
	s.CancelRead = t.readStatus == usUnitExcept
	s.RibbonShift, s.Ribbon, s.WriteRibbon = t.ribbonShift, t.ribbon, t.wRibbon
	s.CarrierColumn, s.WriteColumn, s.HasCarrierColumn = t.column, t.wColumn, true
	s.WriteLines, s.WritePartial, s.WriteData, s.WriteReturn = t.wLines, t.wPart, t.wData, t.wCR
	return encodeGob(s)
}

func (t *Console1052) restore(data []byte, _ bool) error {
	var s console3215Snap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	t.restoreConsoleState(s)
	t.notReady, t.readyEnd, t.readStatus = s.NotReady, s.ReadyEnd, s.ReadStatus
	if t.readStatus == 0 && s.CancelRead {
		t.readStatus = usUnitExcept
	}
	t.wLines, t.wPart, t.wData, t.wCR = s.WriteLines, s.WritePartial, s.WriteData, s.WriteReturn
	t.ribbonShift, t.ribbon, t.wRibbon = s.RibbonShift, s.Ribbon, s.WriteRibbon
	if s.HasCarrierColumn {
		t.column, t.wColumn = s.CarrierColumn, s.WriteColumn
	} else {
		t.column, t.wColumn = len([]rune(s.Partial)), len([]rune(s.WritePartial))
	}
	return nil
}

type unitRecordSnap struct {
	Type          uint16
	Cards         [][]byte
	Output        []string
	Sense         byte
	Dropped       int
	Version       uint64
	Buffer        []byte
	Last          byte
	Started       bool
	EOF           bool
	ReadStackers  [3]uint64
	PunchStopped  bool
	PunchPending  bool
	PunchStacker  byte
	PunchStackers [3]uint64
	Punched       [][]byte
	Card1442      []byte
	Column1442    int
	DiagColumns   [160]byte
	DiagReady     bool
	Wide1443      bool
	Burst2821     bool
	ReaderStopped bool
	Printer       printerSnap
	SwitchPaths   [2]uint16
	Control       switch2821State
	Port          unit2821State
}

type printerSnap struct {
	Tape                                                                                    []uint16
	LinesAdvanced                                                                           uint64
	Line                                                                                    int
	SkipMoves, NoUCS, UCSLoaded, UCSGated, BlockCheck, Fold, Dualing, NotReady, Unavailable bool
	UCS                                                                                     [240]byte
	Plane                                                                                   [printBuffer]byte
	ChainPos                                                                                int
	PrevCmd                                                                                 byte
}

func (u *UnitRecord) snapshotKind() string { return fmt.Sprintf("unit-%04X", u.Type) }

func (u *UnitRecord) snapshot() ([]byte, error) {
	s := unitRecordSnap{Type: u.Type, Cards: u.cards, Output: u.Output, Sense: u.sense, Dropped: u.dropped, Version: u.version,
		Buffer: u.buffer, Last: u.last, Started: u.started, EOF: u.eof, ReadStackers: u.readStackers, PunchStopped: u.punchStopped, PunchPending: u.punchPending, PunchStacker: u.punchStacker, PunchStackers: u.punchStackers, Punched: u.punched,
		Card1442: u.card1442, Column1442: u.column1442,
		DiagColumns: u.diagColumns, DiagReady: u.diagReady, Wide1443: u.wide1443, Burst2821: u.burst2821, ReaderStopped: u.readerStopped,
		Printer: printerSnap{Tape: u.pr.tape, Line: u.pr.line, LinesAdvanced: u.pr.linesAdvanced, SkipMoves: u.pr.skipMoves, NoUCS: u.pr.noUCS, UCSLoaded: u.pr.ucsLoaded,
			UCSGated: u.pr.ucsGated, BlockCheck: u.pr.blockCheck, Fold: u.pr.fold, Dualing: u.pr.dualing, NotReady: u.pr.notReady, Unavailable: u.pr.unavailable, UCS: u.pr.ucs, Plane: u.pr.plane,
			ChainPos: u.chainPos, PrevCmd: u.prevCmd}}
	if u.port != nil {
		s.SwitchPaths = [2]uint16{u.port.paths[0].devno, u.port.paths[1].devno}
		s.Control, s.Port = u.port.control.state, u.port.state
	}
	return encodeGob(s)
}

func (u *UnitRecord) restore(data []byte, _ bool) error {
	var s unitRecordSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	if s.Wide1443 != u.wide1443 {
		return fmt.Errorf("unit record %04X: snapshot has different 1443 print width", u.devno)
	}
	var paths [2]uint16
	if u.port != nil {
		paths = [2]uint16{u.port.paths[0].devno, u.port.paths[1].devno}
	}
	if paths != s.SwitchPaths {
		return fmt.Errorf("unit record %04X: snapshot has different 2821 interfaces", u.devno)
	}
	u.burst2821 = s.Burst2821
	u.readerStopped = s.ReaderStopped
	if u.port != nil {
		u.port.control.state, u.port.state = s.Control, s.Port
	}
	u.cards, u.Output, u.sense, u.dropped = s.Cards, s.Output, s.Sense, s.Dropped
	u.buffer, u.last, u.started, u.eof = s.Buffer, s.Last, s.Started, s.EOF
	u.readStackers = s.ReadStackers
	u.punchStopped, u.punched = s.PunchStopped, s.Punched
	u.card1442, u.column1442 = s.Card1442, s.Column1442
	u.punchPending, u.punchStacker, u.punchStackers = s.PunchPending, s.PunchStacker, s.PunchStackers
	u.diagColumns, u.diagReady = s.DiagColumns, s.DiagReady
	p := s.Printer
	u.pr = printer{tape: p.Tape, line: p.Line, linesAdvanced: p.LinesAdvanced, skipMoves: p.SkipMoves, noUCS: p.NoUCS, ucsLoaded: p.UCSLoaded, ucsGated: p.UCSGated,
		blockCheck: p.BlockCheck, fold: p.Fold, dualing: p.Dualing, notReady: p.NotReady, unavailable: p.Unavailable, ucs: p.UCS, plane: p.Plane}
	u.chainPos, u.prevCmd = p.ChainPos, p.PrevCmd
	u.version = max(u.version, s.Version) + 1
	return nil
}

type tapeSnap struct {
	Blocks               int
	Pos                  int
	Unloaded             bool
	Sense                [24]byte
	PastLoadPoint        bool
	LastCommand          byte
	SevenTrack           bool
	SevenMode            byte
	NoConverter          bool
	DualDensity          bool
	PEOnly2415           bool // legacy field name, also used by PE-only 2401s
	TransportModel       uint8
	ModeCompatible       bool
	GoInhibitUntil       uint64
	ReadMotionEnd        uint64
	GoDelay              time.Duration
	WritePE              bool
	TransferPE           bool
	EraseDensity         int
	ReelEOT              int64
	ReelPosition         int64
	BlankTravel          int64
	TapeIndicate         bool
	FileProtected        bool
	WriteCheckRecord     int
	WriteChecks          int
	Manual2415           bool
	ReadyArmed2415       bool
	WriteMode2415        bool
	Backward2415         bool
	Turnaround2415       time.Duration
	LoadPoint2415        time.Duration
	UnloadUntil2415      uint64
	Reload2415           byte
	ReadyEnd2415         bool
	RewindDisconnect2415 uint64
}

func (t *Tape3420) snapshotKind() string { return "3420" }

func (t *Tape3420) snapshot() ([]byte, error) {
	return encodeGob(tapeSnap{Blocks: len(t.blocks), Pos: t.pos, Unloaded: t.unloaded, Sense: t.sense,
		PastLoadPoint: t.pastLoadPoint, LastCommand: t.lastCommand, SevenTrack: t.sevenTrack, SevenMode: t.sevenMode,
		NoConverter: t.noConverter, DualDensity: t.dualDensity, PEOnly2415: t.peOnly, TransportModel: t.transportModel, ModeCompatible: t.modeCompatible,
		GoInhibitUntil: t.goInhibitUntil, ReadMotionEnd: t.readMotionEnd, GoDelay: t.goDelay,
		WritePE: t.writePE, TransferPE: t.transferPE, EraseDensity: t.eraseDensity,
		ReelEOT: t.reelEOT, ReelPosition: t.reelPosition, BlankTravel: t.blankTravel, TapeIndicate: t.tapeIndicate, FileProtected: t.fileProtected,
		WriteCheckRecord: t.writeCheckRecord, WriteChecks: t.writeChecks, Manual2415: t.manual, ReadyArmed2415: t.readyArmed,
		Backward2415: t.backward, WriteMode2415: t.writeMode, Turnaround2415: t.turnaround, LoadPoint2415: t.loadPointDelay,
		UnloadUntil2415: t.unloadUntil, Reload2415: t.reload, ReadyEnd2415: t.readyEnd, RewindDisconnect2415: t.rewindDisconnect})
}

func (t *Tape3420) restore(data []byte, _ bool) error {
	var s tapeSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	if s.Blocks != len(t.blocks) {
		return fmt.Errorf("tape has %d blocks, checkpoint %d (tapes written in a session are not saved)", len(t.blocks), s.Blocks)
	}
	if s.SevenTrack != t.sevenTrack || s.NoConverter != t.noConverter || s.DualDensity != t.dualDensity || s.PEOnly2415 != t.peOnly {
		return fmt.Errorf("tape track configuration differs from checkpoint")
	}
	if s.TransportModel != t.transportModel || s.ModeCompatible != t.modeCompatible {
		return fmt.Errorf("tape transport model differs from checkpoint")
	}
	if s.ReelEOT != t.reelEOT {
		return fmt.Errorf("tape reel configuration differs from checkpoint")
	}
	t.pos, t.unloaded, t.sense = s.Pos, s.Unloaded, s.Sense
	t.pastLoadPoint, t.lastCommand = s.PastLoadPoint, s.LastCommand
	t.sevenMode, t.fileProtected = s.SevenMode, s.FileProtected
	t.goInhibitUntil, t.readMotionEnd, t.goDelay = s.GoInhibitUntil, s.ReadMotionEnd, s.GoDelay
	t.writePE, t.transferPE, t.eraseDensity = s.WritePE, s.TransferPE, s.EraseDensity
	t.reelPosition, t.tapeIndicate = s.ReelPosition, s.TapeIndicate
	t.blankTravel = s.BlankTravel
	t.writeCheckRecord, t.writeChecks = s.WriteCheckRecord, s.WriteChecks
	t.manual, t.readyArmed = s.Manual2415, s.ReadyArmed2415
	t.backward, t.writeMode, t.turnaround = s.Backward2415, s.WriteMode2415, s.Turnaround2415
	t.loadPointDelay = s.LoadPoint2415
	t.unloadUntil, t.reload = s.UnloadUntil2415, s.Reload2415
	t.readyEnd = s.ReadyEnd2415
	t.rewindDisconnect = s.RewindDisconnect2415
	return nil
}

// DASDOverlays reports the written-track count of every DASD, by device.
func (m *Machine) DASDOverlays() map[uint16]int {
	out := map[uint16]int{}
	for _, x := range m.CSS.subs {
		if d, ok := x.dev.(*DASD3390); ok {
			out[x.devno] = d.OverlayTracks()
		}
	}
	return out
}

type ctciSnap struct {
	Write bool
	Sense byte
	Queue [][]byte
}

func (d *ctciSide) snapshotKind() string { return "ctci" }

func (d *ctciSide) snapshot() ([]byte, error) {
	s := ctciSnap{Write: d.write, Sense: d.sense}
	if !d.write {
		s.Queue = d.c.queue // the pair's queue, kept with its first device
	}
	return encodeGob(s)
}

func (d *ctciSide) restore(data []byte, _ bool) error {
	var s ctciSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	if s.Write != d.write {
		return errorString("ctc: read and write devices swapped")
	}
	d.sense = s.Sense
	if !d.write {
		d.c.queue, d.c.queued = s.Queue, 0
		for _, p := range s.Queue {
			d.c.queued += len(p)
		}
		d.c.version++
	}
	return nil
}
