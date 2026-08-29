package ese

import (
	"encoding/binary"
	"fmt"
)

func (b *builder) buildDatabaseSpace(databasePages, allocatedLast uint32) error {
	if err := b.put(encodedPage{
		dbtime: b.dbtime, flags: pageFlagRoot | pageFlagLeaf | pageFlagNewRecord,
		number: 1, objid: 1, values: [][]byte{spaceHeader(databasePages, 0, 1, 2)},
	}); err != nil {
		return err
	}
	available := []pageExtent(nil)
	if allocatedLast < databasePages {
		available = append(available, pageExtent{first: allocatedLast + 1, count: databasePages - allocatedLast})
	}
	return b.putSpacePair(2, 3, 1, []pageExtent{{first: 1, count: databasePages}}, available, false)
}

func (b *builder) databaseHeader() ([]byte, error) {
	header := make([]byte, b.options.PageSize)
	binary.LittleEndian.PutUint32(header[4:8], 0x89abcdef)
	binary.LittleEndian.PutUint32(header[8:12], b.options.Version)
	binary.LittleEndian.PutUint64(header[16:24], b.dbtime)
	// A deterministic, non-null database signature. No log signature is set;
	// this is a clean standalone database and ESENT will establish a matching
	// log generation when it first attaches read/write.
	binary.LittleEndian.PutUint32(header[24:28], 1)
	header[28], header[29], header[30] = 1, 1, 1
	binary.LittleEndian.PutUint32(header[52:56], 3) // JET_dbstateCleanShutdown
	binary.LittleEndian.PutUint32(header[104:108], 1)
	binary.LittleEndian.PutUint32(header[212:216], b.objidLast)
	binary.LittleEndian.PutUint32(header[216:220], 6)
	binary.LittleEndian.PutUint32(header[220:224], 3)
	binary.LittleEndian.PutUint32(header[224:228], 9600)
	binary.LittleEndian.PutUint32(header[232:236], b.options.Revision)
	binary.LittleEndian.PutUint32(header[236:240], uint32(b.options.PageSize))
	binary.LittleEndian.PutUint32(header[340:344], b.options.Version)
	binary.LittleEndian.PutUint32(header[344:348], b.options.Revision)
	binary.LittleEndian.PutUint64(header[508:516], ^uint64(0))
	binary.LittleEndian.PutUint32(header[667:671], 0)
	checksum, err := oldChecksum(header)
	if err != nil {
		return nil, fmt.Errorf("ese: database header: %w", err)
	}
	binary.LittleEndian.PutUint32(header[:4], checksum)
	return header, nil
}
