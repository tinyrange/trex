// Package perf reads bounded, little-endian PERFILE2 sampling captures.
// It follows Linux's perf_event UAPI and tools/perf file header, without
// executing perf or depending on host files, processes, or byte order.
package perf

const (
	SampleIP         uint64 = 1 << 0
	SampleTID        uint64 = 1 << 1
	SampleTime       uint64 = 1 << 2
	SampleAddress    uint64 = 1 << 3
	SampleID         uint64 = 1 << 6
	SampleCPU        uint64 = 1 << 7
	SamplePeriod     uint64 = 1 << 8
	SampleStreamID   uint64 = 1 << 9
	SampleIdentifier uint64 = 1 << 16
)

type Options struct {
	MaximumRecords     int
	MaximumSamples     int
	MaximumStringBytes int
}

type Attribute struct {
	Type, Size                                          uint32
	Config, SamplePeriod, SampleType, ReadFormat, Flags uint64
	ClockID                                             int32
	UseClockID, SampleIDAll                             bool
	IDs                                                 []uint64
}

// Present uses PERF_SAMPLE_* bits. Zero values are not evidence of absence.
type Fields struct {
	Present                                             uint64
	IP, Time, Address, ID, StreamID, Identifier, Period uint64
	PID, TID, CPU                                       uint32
}

type Sample struct {
	Offset uint64
	Misc   uint16
	Fields Fields
}

type Mapping struct {
	Offset                      uint64
	Misc                        uint16
	Type                        uint32
	PID, TID                    uint32
	Address, Length, PageOffset uint64
	Major, Minor                uint32
	Inode, InodeGeneration      uint64
	Prot, Flags                 uint32
	BuildID                     []byte
	Filename                    string
	SampleID                    Fields
}

type Comm struct {
	Offset   uint64
	Misc     uint16
	PID, TID uint32
	Name     string
	SampleID Fields
}

type LostRecord struct {
	Offset    uint64
	Misc      uint16
	Type      uint32
	ID, Count uint64
	SampleID  Fields
}

// Offsets retain file order across record lists. UnknownRecords explicitly
// counts unparsed kinds; callers must assess those before treating a capture
// as complete. Samples are raw observations, not symbolized or time-sorted.
type File struct {
	LittleEndian   bool
	Attributes     []Attribute
	Samples        []Sample
	Mappings       []Mapping
	Comms          []Comm
	Lost           []LostRecord
	TotalLost      uint64
	UnknownRecords map[uint32]uint64
	Records        uint64
}
