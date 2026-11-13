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
	"strings"

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
	S370             bool
	MemSize          int
	KeyShift         uint
	TOD, LastStck    uint64
	TODProgrammable  uint16
	ServiceSignal    bool
	ServiceParam     uint32
	InputWake        bool
	LoadParm         string
	SCPConfig        [6]byte
	Facilities       uint32
	SCPCPUFacilities [12]byte
	SCLP             sclpSnap
	CPUs             []cpuSnap
	Subchannels      []subSnap
	CRW              []uint32
	CRWPend          bool
	Devices          []devSnap
	Mem, Keys        []byte
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
	Addr              uint16
	GR, AR, CR        [16]uint32
	FPR               [16]uint64
	FPC               uint32
	PSW               PSW
	Prefix            uint32
	ClockComparator   uint64
	Amask, PgMask     uint32
	ITBase, ITDone    uint64
	ITPending         bool
	Stopped, Check    bool
	CheckReason       string
	ExtPending        uint32
	Emergency         uint64
	ExtCallFrom       uint16
	TimerValue        int64
	TimerRef          uint64
	Instructions      uint64
	SIEEntries        uint64
	DXC               byte
	ExcAddr, ExcSpace uint32
	SIE               *sieSnap // interpretive execution in progress
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
	AttnHold                         bool
	Blocked                          bool
	BlockAddr                        uint32
	BlockFmt1, PCIWait, PCIInterrupt bool
	PCIAt                            uint64
}

type devSnap struct {
	Devno uint16
	Kind  string
	Data  []byte
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
	s := &machineSnap{S370: m.S370, MemSize: len(m.S.Mem), KeyShift: m.S.KeyShift,
		TOD: m.tod, LastStck: m.lastStck, TODProgrammable: m.todProgrammable,
		ServiceSignal: m.serviceSignal, ServiceParam: m.serviceParam, InputWake: m.inputWake,
		LoadParm: m.LoadParm, SCPConfig: m.SCPConfig, Facilities: m.Facilities, SCPCPUFacilities: m.SCPCPUFacilities,
		CRW: append([]uint32(nil), m.CSS.crw...), CRWPend: m.CSS.crwPend,
		Mem: append([]byte(nil), m.S.Mem...), Keys: append([]byte(nil), m.S.Keys...)}
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
			DXC: c.dxc, ExcAddr: c.excAddr, ExcSpace: c.excSpace})
	}
	for _, x := range m.CSS.subs {
		s.Subchannels = append(s.Subchannels, subSnap{Num: x.num, Devno: x.devno, Intparm: x.intparm, ISC: x.isc,
			Enabled: x.enabled, LPM: x.lpm, MBI: x.mbi, MM: x.mm, Limit: x.limit, Multipath: x.multip, Timing: x.timing,
			Key: x.key, CCWFmt: x.ccwfmt, Flags: x.flags, FC: x.fc, AC: x.ac, SC: x.sc, CCWAddr: x.ccwaddr,
			DevStatus: x.devStatus, SchStatus: x.schStatus, Residual: x.residual, Pending: x.pending, IRQ: x.irq,
			CCDeferred: x.ccDeferred, Sense: append([]byte(nil), x.sense...), AttnHold: x.attnHold,
			Blocked: x.blocked, BlockAddr: x.blockAddr, BlockFmt1: x.blockFmt1, PCIWait: x.pciWait,
			PCIInterrupt: x.pciIRQ, PCIAt: x.pciAt})
		sn, ok := x.dev.(snapshotter)
		if !ok {
			return nil, fmt.Errorf("s390: device %04X (%T) cannot be checkpointed", x.devno, x.dev)
		}
		data, err := sn.snapshot()
		if err != nil {
			return nil, fmt.Errorf("s390: device %04X: %w", x.devno, err)
		}
		s.Devices = append(s.Devices, devSnap{Devno: x.devno, Kind: sn.snapshotKind(), Data: data})
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
	if s.S370 != m.S370 || s.MemSize != len(m.S.Mem) || len(s.CPUs) != len(m.CPUs) {
		return fmt.Errorf("s390: checkpoint is of a different machine (%d bytes, %d CPUs, S/370 %v)", s.MemSize, len(s.CPUs), s.S370)
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
		if !ok || !can || sn.snapshotKind() != d.Kind {
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
	m.tod, m.lastStck, m.todProgrammable = s.TOD, s.LastStck, s.TODProgrammable
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
		c.Instructions, c.SIEEntries, c.dxc = cs.Instructions, cs.SIEEntries, cs.DXC
		c.excAddr, c.excSpace = cs.ExcAddr, cs.ExcSpace
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
		x.intparm, x.isc, x.enabled, x.lpm, x.mbi = ss.Intparm, ss.ISC, ss.Enabled, ss.LPM, ss.MBI
		x.mm, x.limit, x.multip, x.timing = ss.MM, ss.Limit, ss.Multipath, ss.Timing
		x.key, x.ccwfmt, x.flags, x.fc, x.ac, x.sc = ss.Key, ss.CCWFmt, ss.Flags, ss.FC, ss.AC, ss.SC
		x.ccwaddr, x.devStatus, x.schStatus, x.residual = ss.CCWAddr, ss.DevStatus, ss.SchStatus, ss.Residual
		x.pending, x.irq, x.ccDeferred, x.sense, x.attnHold = ss.Pending, ss.IRQ, ss.CCDeferred, ss.Sense, ss.AttnHold
		x.blocked, x.blockAddr, x.blockFmt1 = ss.Blocked, ss.BlockAddr, ss.BlockFmt1
		x.pciWait, x.pciIRQ, x.pciAt = ss.PCIWait, ss.PCIInterrupt, ss.PCIAt
	}
	m.CSS.crw, m.CSS.crwPend = s.CRW, s.CRWPend
	return nil
}

// --- devices ---------------------------------------------------------------

type dasdSnap struct {
	Fingerprint                   []byte
	Overlay                       map[uint32][]ckd.Record
	Cyl, Head                     uint32
	Rec                           int
	AfterData, AfterKey           bool
	IndexPass                     int
	Extent                        bool
	Mask                          byte
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
	return encodeGob(dasdSnap{Fingerprint: fp, Overlay: overlay, Cyl: d.cyl, Head: d.head, Rec: d.rec,
		AfterData: d.afterData, AfterKey: d.afterKey, IndexPass: d.indexPass, Extent: d.extent, Mask: d.mask,
		ExtBeg: d.extBeg, ExtEnd: d.extEnd, Locate: d.locate, LROp: d.lrOp, LRCount: d.lrCount, LROrient: d.lrOrient,
		LRSearch: d.lrSearch, LRSearched: d.lrSearched, LRFirst: d.lrFirst, Sense: d.sense, RSSD: d.rssd,
		Reserved: d.reserved, PGID: d.pgid, Chained: d.chained, PrevCmd: d.prevCmd,
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
	if d.overlay == nil {
		d.overlay = map[uint32][]ckd.Record{}
	}
	if disksOnly {
		return nil
	}
	d.cyl, d.head, d.rec, d.afterData, d.afterKey, d.indexPass = s.Cyl, s.Head, s.Rec, s.AfterData, s.AfterKey, s.IndexPass
	d.extent, d.mask, d.extBeg, d.extEnd = s.Extent, s.Mask, s.ExtBeg, s.ExtEnd
	d.locate, d.lrOp, d.lrCount, d.lrOrient, d.lrSearch, d.lrSearched, d.lrFirst = s.Locate, s.LROp, s.LRCount, s.LROrient, s.LRSearch, s.LRSearched, s.LRFirst
	d.sense, d.rssd, d.reserved, d.pgid, d.chained, d.prevCmd = s.Sense, s.RSSD, s.Reserved, s.PGID, s.Chained, s.PrevCmd
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
	Lines   []string
	Partial string
	Input   []string
	Sense   byte
	Dropped int
	Version uint64
}

func (t *Console3215) snapshotKind() string { return "3215" }

func (t *Console3215) snapshot() ([]byte, error) {
	return encodeGob(console3215Snap{Lines: t.Lines, Partial: t.Partial, Input: t.input, Sense: t.sense,
		Dropped: t.dropped, Version: t.version})
}

func (t *Console3215) restore(data []byte, _ bool) error {
	var s console3215Snap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	t.Lines, t.Partial, t.input, t.sense, t.dropped = s.Lines, s.Partial, s.Input, s.Sense, s.Dropped
	t.version = max(t.version, s.Version) + 1
	return nil
}

type unitRecordSnap struct {
	Type    uint16
	Cards   [][]byte
	Output  []string
	Sense   byte
	Dropped int
	Version uint64
}

func (u *UnitRecord) snapshotKind() string { return fmt.Sprintf("unit-%04X", u.Type) }

func (u *UnitRecord) snapshot() ([]byte, error) {
	return encodeGob(unitRecordSnap{Type: u.Type, Cards: u.cards, Output: u.Output, Sense: u.sense, Dropped: u.dropped, Version: u.version})
}

func (u *UnitRecord) restore(data []byte, _ bool) error {
	var s unitRecordSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	u.cards, u.Output, u.sense, u.dropped = s.Cards, s.Output, s.Sense, s.Dropped
	u.version = max(u.version, s.Version) + 1
	return nil
}

type tapeSnap struct {
	Blocks   int
	Pos      int
	Unloaded bool
	Sense    [24]byte
}

func (t *Tape3420) snapshotKind() string { return "3420" }

func (t *Tape3420) snapshot() ([]byte, error) {
	return encodeGob(tapeSnap{Blocks: len(t.blocks), Pos: t.pos, Unloaded: t.unloaded, Sense: t.sense})
}

func (t *Tape3420) restore(data []byte, _ bool) error {
	var s tapeSnap
	if err := decodeGob(data, &s); err != nil {
		return err
	}
	if s.Blocks != len(t.blocks) {
		return fmt.Errorf("tape has %d blocks, checkpoint %d (tapes written in a session are not saved)", len(t.blocks), s.Blocks)
	}
	t.pos, t.unloaded, t.sense = s.Pos, s.Unloaded, s.Sense
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
