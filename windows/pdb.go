package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

const (
	pdbMSFMagic           = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
	pdbMSF20Magic         = "Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00"
	pdbDefaultStreamLimit = 256 << 20
)

type pdbSymbol struct {
	name string
	rva  uint32
	kind string
}

type pdbMSF struct {
	file        starfile.File
	blockSize   uint32
	numBlocks   uint32
	sizes       []uint32
	streams     [][]uint32
	streamLimit int64
	version     int
}

type pdbValue struct {
	guid      string
	age       uint32
	signature uint32
	symbols   []pdbSymbol
}

func windowsPDBBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	streamLimit := int64(pdbDefaultStreamLimit)
	if err := starlark.UnpackArgs("pdb", args, kwargs, "file", &file, "stream_limit?", &streamLimit); err != nil {
		return nil, err
	}
	if streamLimit <= 0 || streamLimit > 1<<30 {
		return nil, fmt.Errorf("pdb: invalid stream_limit")
	}
	return parsePDB(file, streamLimit)
}

func parsePDB(file starfile.File, streamLimit int64) (*pdbValue, error) {
	msf, err := parsePDBMSF(file, streamLimit)
	if err != nil {
		return nil, err
	}
	info, err := msf.stream(1)
	if err != nil {
		return nil, fmt.Errorf("PDB info stream: %w", err)
	}
	if len(info) < 12 {
		return nil, fmt.Errorf("PDB info stream is short")
	}
	value := &pdbValue{signature: binary.LittleEndian.Uint32(info[4:8]), age: binary.LittleEndian.Uint32(info[8:12])}
	if msf.version >= 7 {
		if len(info) < 28 {
			return nil, fmt.Errorf("PDB info stream has no GUID")
		}
		value.guid = formatPDBGUID(info[12:28])
	}
	value.symbols, err = parsePDBSymbolStreams(msf)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func parsePDBSymbolStreams(msf *pdbMSF) ([]pdbSymbol, error) {
	dbi, err := msf.stream(3)
	if err != nil {
		return nil, fmt.Errorf("PDB DBI stream: %w", err)
	}
	if len(dbi) < 64 {
		return nil, fmt.Errorf("PDB DBI stream is short")
	}
	symbolStream := int(binary.LittleEndian.Uint16(dbi[20:22]))
	omapStream, err := pdbOptionalDebugStream(dbi, 4)
	if err != nil {
		return nil, err
	}
	sectionStream, err := pdbSectionHeaderStream(dbi, omapStream != 0xffff)
	if err != nil {
		return nil, err
	}
	sections, err := msf.stream(sectionStream)
	if err != nil {
		return nil, fmt.Errorf("PDB section stream: %w", err)
	}
	sectionRVAs := make([]uint32, 0, len(sections)/40)
	for offset := 0; offset+40 <= len(sections); offset += 40 {
		sectionRVAs = append(sectionRVAs, binary.LittleEndian.Uint32(sections[offset+12:offset+16]))
	}
	records, err := msf.stream(symbolStream)
	if err != nil {
		return nil, fmt.Errorf("PDB symbol stream: %w", err)
	}
	symbols := appendPDBSymbols(nil, records, sectionRVAs)
	moduleInfoSize := int(binary.LittleEndian.Uint32(dbi[24:28]))
	if moduleInfoSize < 0 || moduleInfoSize > len(dbi)-64 {
		return nil, fmt.Errorf("PDB module info substream is invalid")
	}
	moduleInfo := dbi[64 : 64+moduleInfoSize]
	for offset := 0; offset < len(moduleInfo); {
		if offset+64 > len(moduleInfo) {
			return nil, fmt.Errorf("short PDB module info record")
		}
		streamIndex := int(binary.LittleEndian.Uint16(moduleInfo[offset+34 : offset+36]))
		symbolBytes := int(binary.LittleEndian.Uint32(moduleInfo[offset+36 : offset+40]))
		nameEnd := bytes.IndexByte(moduleInfo[offset+64:], 0)
		if nameEnd < 0 {
			return nil, fmt.Errorf("unterminated PDB module name")
		}
		objectStart := offset + 64 + nameEnd + 1
		objectEnd := bytes.IndexByte(moduleInfo[objectStart:], 0)
		if objectEnd < 0 {
			return nil, fmt.Errorf("unterminated PDB object name")
		}
		offset = (objectStart + objectEnd + 1 + 3) &^ 3
		if streamIndex == 0xffff || symbolBytes <= 4 {
			continue
		}
		stream, err := msf.stream(streamIndex)
		if err != nil {
			return nil, fmt.Errorf("PDB module stream %d: %w", streamIndex, err)
		}
		if symbolBytes > len(stream) {
			return nil, fmt.Errorf("PDB module symbols exceed stream %d", streamIndex)
		}
		symbols = appendPDBSymbols(symbols, stream[4:symbolBytes], sectionRVAs)
	}
	if omapStream != 0xffff {
		omap, err := msf.stream(omapStream)
		if err != nil {
			return nil, fmt.Errorf("PDB OMAP stream: %w", err)
		}
		symbols = applyPDBOMap(symbols, omap)
	}
	sort.Slice(symbols, func(left, right int) bool {
		if symbols[left].rva != symbols[right].rva {
			return symbols[left].rva < symbols[right].rva
		}
		if symbols[left].kind != symbols[right].kind {
			return symbols[left].kind < symbols[right].kind
		}
		return symbols[left].name < symbols[right].name
	})
	return symbols, nil
}

func parsePDBMSF(file starfile.File, streamLimit int64) (*pdbMSF, error) {
	header := make([]byte, 60)
	if _, err := readFullAt(file, header, 0); err != nil {
		return nil, fmt.Errorf("PDB/MSF header: %w", err)
	}
	if string(header[:32]) == pdbMSFMagic {
		return parsePDBMSF7(file, streamLimit, header)
	}
	if string(header[:44]) == pdbMSF20Magic {
		return parsePDBMSF2(file, streamLimit, header)
	}
	return nil, fmt.Errorf("unsupported PDB/MSF header")
}

func parsePDBMSF7(file starfile.File, streamLimit int64, header []byte) (*pdbMSF, error) {
	blockSize := binary.LittleEndian.Uint32(header[32:36])
	numBlocks := binary.LittleEndian.Uint32(header[40:44])
	directorySize := binary.LittleEndian.Uint32(header[44:48])
	blockMap := binary.LittleEndian.Uint32(header[52:56])
	if blockSize < 512 || blockSize > 1<<20 || blockSize&(blockSize-1) != 0 || numBlocks == 0 || uint64(numBlocks)*uint64(blockSize) > uint64(file.Size()) {
		return nil, fmt.Errorf("invalid PDB/MSF geometry")
	}
	if int64(directorySize) > streamLimit {
		return nil, fmt.Errorf("PDB/MSF directory exceeds stream limit")
	}
	directoryBlocks := (directorySize + blockSize - 1) / blockSize
	mapSize := int64(directoryBlocks) * 4
	mapOffset := int64(blockMap) * int64(blockSize)
	if validateBlockRange(file.Size(), mapOffset, mapSize) != nil {
		return nil, fmt.Errorf("PDB/MSF block map exceeds file")
	}
	mapData := make([]byte, mapSize)
	if _, err := readFullAt(file, mapData, mapOffset); err != nil {
		return nil, err
	}
	directory := make([]byte, 0, int64(directoryBlocks)*int64(blockSize))
	for index := uint32(0); index < directoryBlocks; index++ {
		block := binary.LittleEndian.Uint32(mapData[index*4 : index*4+4])
		contents, err := pdbMSFBlock(file, blockSize, numBlocks, block)
		if err != nil {
			return nil, err
		}
		directory = append(directory, contents...)
	}
	directory = directory[:directorySize]
	if len(directory) < 4 {
		return nil, fmt.Errorf("short PDB/MSF directory")
	}
	streamCount := int(binary.LittleEndian.Uint32(directory[:4]))
	if streamCount < 0 || streamCount > 1<<20 || 4+streamCount*4 > len(directory) {
		return nil, fmt.Errorf("invalid PDB/MSF stream count")
	}
	msf := &pdbMSF{file: file, blockSize: blockSize, numBlocks: numBlocks, sizes: make([]uint32, streamCount), streams: make([][]uint32, streamCount), streamLimit: streamLimit, version: 7}
	offset := 4
	for index := range msf.sizes {
		msf.sizes[index] = binary.LittleEndian.Uint32(directory[offset : offset+4])
		offset += 4
	}
	for index, size := range msf.sizes {
		if size == ^uint32(0) {
			continue
		}
		if int64(size) > streamLimit {
			return nil, fmt.Errorf("PDB/MSF stream %d exceeds limit", index)
		}
		blocks := int((size + blockSize - 1) / blockSize)
		if blocks > (len(directory)-offset)/4 {
			return nil, fmt.Errorf("PDB/MSF stream %d block list exceeds directory", index)
		}
		msf.streams[index] = make([]uint32, blocks)
		for block := range msf.streams[index] {
			msf.streams[index][block] = binary.LittleEndian.Uint32(directory[offset : offset+4])
			offset += 4
		}
	}
	return msf, nil
}

func parsePDBMSF2(file starfile.File, streamLimit int64, header []byte) (*pdbMSF, error) {
	blockSize := binary.LittleEndian.Uint32(header[44:48])
	numBlocks := uint32(binary.LittleEndian.Uint16(header[50:52]))
	directorySize := binary.LittleEndian.Uint32(header[52:56])
	if blockSize < 512 || blockSize > 1<<20 || blockSize&(blockSize-1) != 0 || numBlocks == 0 || uint64(numBlocks)*uint64(blockSize) > uint64(file.Size()) {
		return nil, fmt.Errorf("invalid PDB/MSF 2.00 geometry")
	}
	if int64(directorySize) > streamLimit {
		return nil, fmt.Errorf("PDB/MSF directory exceeds stream limit")
	}
	directoryBlocks := (directorySize + blockSize - 1) / blockSize
	blockListSize := int64(directoryBlocks) * 2
	if validateBlockRange(file.Size(), 60, blockListSize) != nil {
		return nil, fmt.Errorf("PDB/MSF 2.00 directory block list exceeds file")
	}
	blockList := make([]byte, blockListSize)
	if _, err := readFullAt(file, blockList, 60); err != nil {
		return nil, err
	}
	directory := make([]byte, 0, int64(directoryBlocks)*int64(blockSize))
	for index := uint32(0); index < directoryBlocks; index++ {
		block := uint32(binary.LittleEndian.Uint16(blockList[index*2 : index*2+2]))
		contents, err := pdbMSFBlock(file, blockSize, numBlocks, block)
		if err != nil {
			return nil, err
		}
		directory = append(directory, contents...)
	}
	directory = directory[:directorySize]
	if len(directory) < 4 {
		return nil, fmt.Errorf("short PDB/MSF 2.00 directory")
	}
	streamCount := int(binary.LittleEndian.Uint16(directory[:2]))
	descriptorsEnd := 4 + streamCount*8
	if streamCount > 1<<16 || descriptorsEnd > len(directory) {
		return nil, fmt.Errorf("invalid PDB/MSF 2.00 stream count")
	}
	msf := &pdbMSF{file: file, blockSize: blockSize, numBlocks: numBlocks, sizes: make([]uint32, streamCount), streams: make([][]uint32, streamCount), streamLimit: streamLimit, version: 2}
	for index := range msf.sizes {
		msf.sizes[index] = binary.LittleEndian.Uint32(directory[4+index*8 : 8+index*8])
	}
	offset := descriptorsEnd
	for index, size := range msf.sizes {
		if size == ^uint32(0) {
			continue
		}
		if int64(size) > streamLimit {
			return nil, fmt.Errorf("PDB/MSF stream %d exceeds limit", index)
		}
		blocks := int((size + blockSize - 1) / blockSize)
		if blocks > (len(directory)-offset)/2 {
			return nil, fmt.Errorf("PDB/MSF 2.00 stream %d block list exceeds directory", index)
		}
		msf.streams[index] = make([]uint32, blocks)
		for block := range msf.streams[index] {
			msf.streams[index][block] = uint32(binary.LittleEndian.Uint16(directory[offset : offset+2]))
			offset += 2
		}
	}
	return msf, nil
}

func (m *pdbMSF) stream(index int) ([]byte, error) {
	if index < 0 || index >= len(m.streams) || m.sizes[index] == ^uint32(0) {
		return nil, fmt.Errorf("stream %d unavailable", index)
	}
	output := make([]byte, 0, int(m.sizes[index]))
	for _, block := range m.streams[index] {
		contents, err := pdbMSFBlock(m.file, m.blockSize, m.numBlocks, block)
		if err != nil {
			return nil, err
		}
		remaining := int(m.sizes[index]) - len(output)
		output = append(output, contents[:min(len(contents), remaining)]...)
	}
	return output, nil
}

func pdbMSFBlock(file starfile.File, blockSize, numBlocks, block uint32) ([]byte, error) {
	if block >= numBlocks {
		return nil, fmt.Errorf("PDB/MSF block %d outside file", block)
	}
	data := make([]byte, blockSize)
	if _, err := readFullAt(file, data, int64(block)*int64(blockSize)); err != nil {
		return nil, err
	}
	return data, nil
}

func appendPDBSymbols(symbols []pdbSymbol, records []byte, sectionRVAs []uint32) []pdbSymbol {
	for offset := 0; offset+4 <= len(records); {
		size := int(binary.LittleEndian.Uint16(records[offset:offset+2])) + 2
		if size < 4 || offset+size > len(records) {
			break
		}
		record := records[offset : offset+size]
		kind := binary.LittleEndian.Uint16(record[2:4])
		if (kind == 0x110e || kind == 0x1009) && len(record) >= 14 {
			section := int(binary.LittleEndian.Uint16(record[12:14]))
			if section > 0 && section <= len(sectionRVAs) {
				name := pdbRecordName(record[14:])
				if kind == 0x1009 {
					name = pdbPascalName(record[14:])
				}
				if name != "" {
					symbols = append(symbols, pdbSymbol{name: name, rva: sectionRVAs[section-1] + binary.LittleEndian.Uint32(record[8:12]), kind: "public"})
				}
			}
		} else if (kind == 0x110f || kind == 0x1110 || kind == 0x1146 || kind == 0x1147 || kind == 0x100a || kind == 0x100b) && len(record) >= 39 {
			section := int(binary.LittleEndian.Uint16(record[36:38]))
			if section > 0 && section <= len(sectionRVAs) {
				name := pdbRecordName(record[39:])
				if kind == 0x100a || kind == 0x100b {
					name = pdbPascalName(record[39:])
				}
				if name != "" {
					symbols = append(symbols, pdbSymbol{name: name, rva: sectionRVAs[section-1] + binary.LittleEndian.Uint32(record[32:36]), kind: "procedure"})
				}
			}
		}
		offset += size
	}
	return symbols
}

func pdbRecordName(data []byte) string {
	if end := bytes.IndexByte(data, 0); end >= 0 {
		data = data[:end]
	}
	return string(data)
}

func pdbPascalName(data []byte) string {
	if len(data) == 0 || int(data[0]) > len(data)-1 {
		return ""
	}
	return string(data[1 : 1+int(data[0])])
}

func applyPDBOMap(symbols []pdbSymbol, data []byte) []pdbSymbol {
	entries := len(data) / 8
	if entries == 0 {
		return symbols
	}
	output := symbols[:0]
	for _, symbol := range symbols {
		index := sort.Search(entries, func(index int) bool { return binary.LittleEndian.Uint32(data[index*8:index*8+4]) > symbol.rva }) - 1
		if index < 0 {
			continue
		}
		source := binary.LittleEndian.Uint32(data[index*8 : index*8+4])
		target := binary.LittleEndian.Uint32(data[index*8+4 : index*8+8])
		if target == 0 {
			continue
		}
		symbol.rva = target + (symbol.rva - source)
		output = append(output, symbol)
	}
	return output
}

func pdbSectionHeaderStream(dbi []byte, original bool) (int, error) {
	indices := []int{5, 10}
	if original {
		indices = []int{10, 5}
	}
	for _, index := range indices {
		stream, err := pdbOptionalDebugStream(dbi, index)
		if err != nil {
			return 0, err
		}
		if stream != 0xffff {
			return stream, nil
		}
	}
	return 0, fmt.Errorf("PDB has no section header stream")
}

func pdbOptionalDebugStream(dbi []byte, index int) (int, error) {
	readSize := func(offset int) (int, error) {
		if offset+4 > len(dbi) {
			return 0, io.ErrUnexpectedEOF
		}
		value := int(int32(binary.LittleEndian.Uint32(dbi[offset : offset+4])))
		if value < 0 {
			return 0, fmt.Errorf("negative DBI substream size")
		}
		return value, nil
	}
	offset := 64
	for _, field := range []int{24, 28, 32, 36, 40} {
		size, err := readSize(field)
		if err != nil {
			return 0, err
		}
		offset += size
	}
	ecSize, err := readSize(52)
	if err != nil {
		return 0, err
	}
	offset += ecSize
	optionalSize, err := readSize(48)
	if err != nil {
		return 0, err
	}
	entryOffset := index * 2
	if entryOffset < 0 || optionalSize < entryOffset+2 || offset+optionalSize > len(dbi) {
		return 0, fmt.Errorf("PDB optional debug header is invalid")
	}
	return int(binary.LittleEndian.Uint16(dbi[offset+entryOffset : offset+entryOffset+2])), nil
}

func formatPDBGUID(data []byte) string {
	if len(data) != 16 {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x", binary.LittleEndian.Uint32(data[0:4]), binary.LittleEndian.Uint16(data[4:6]), binary.LittleEndian.Uint16(data[6:8]), data[8], data[9], data[10:16]))
}

func (p *pdbValue) String() string {
	return fmt.Sprintf("<windows.pdb guid=%s age=%d symbols=%d>", p.guid, p.age, len(p.symbols))
}
func (p *pdbValue) Type() string          { return "windows.pdb" }
func (p *pdbValue) Freeze()               {}
func (p *pdbValue) Truth() starlark.Bool  { return starlark.True }
func (p *pdbValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", p.Type()) }
func (p *pdbValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "guid":
		return starlark.String(p.guid), nil
	case "age":
		return starlark.MakeUint64(uint64(p.age)), nil
	case "signature":
		return starlark.MakeUint64(uint64(p.signature)), nil
	case "symbols":
		return pdbSymbolsValue(p.symbols), nil
	case "find":
		return starlark.NewBuiltin("find", p.findBuiltin), nil
	case "nearest":
		return starlark.NewBuiltin("nearest", p.nearestBuiltin), nil
	}
	return nil, nil
}
func (p *pdbValue) AttrNames() []string {
	return []string{"age", "find", "guid", "nearest", "signature", "symbols"}
}

type pdbSymbolValue struct{ symbol pdbSymbol }

func (v *pdbSymbolValue) String() string {
	return fmt.Sprintf("<windows.pdb_symbol %s+%#x>", v.symbol.name, v.symbol.rva)
}
func (v *pdbSymbolValue) Type() string          { return "windows.pdb_symbol" }
func (v *pdbSymbolValue) Freeze()               {}
func (v *pdbSymbolValue) Truth() starlark.Bool  { return starlark.True }
func (v *pdbSymbolValue) Hash() (uint32, error) { return starlark.String(v.symbol.name).Hash() }
func (v *pdbSymbolValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(v.symbol.name), nil
	case "rva":
		return starlark.MakeUint64(uint64(v.symbol.rva)), nil
	case "kind":
		return starlark.String(v.symbol.kind), nil
	}
	return nil, nil
}
func (v *pdbSymbolValue) AttrNames() []string { return []string{"kind", "name", "rva"} }

func pdbSymbolsValue(symbols []pdbSymbol) *starlark.List {
	values := make([]starlark.Value, len(symbols))
	for index, symbol := range symbols {
		values[index] = &pdbSymbolValue{symbol: symbol}
	}
	return starlark.NewList(values)
}
func (p *pdbValue) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var query string
	exact := false
	if err := starlark.UnpackArgs("find", args, kwargs, "query", &query, "exact?", &exact); err != nil {
		return nil, err
	}
	query = strings.ToLower(query)
	var symbols []pdbSymbol
	for _, symbol := range p.symbols {
		name := strings.ToLower(symbol.name)
		if exact && name == query || !exact && strings.Contains(name, query) {
			symbols = append(symbols, symbol)
		}
	}
	return pdbSymbolsValue(symbols), nil
}
func (p *pdbValue) nearestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rva uint64
	if err := starlark.UnpackArgs("nearest", args, kwargs, "rva", &rva); err != nil {
		return nil, err
	}
	if rva > ^uint64(uint32(0)) {
		return nil, fmt.Errorf("nearest: RVA exceeds 32 bits")
	}
	index := sort.Search(len(p.symbols), func(index int) bool { return uint64(p.symbols[index].rva) > rva }) - 1
	if index < 0 {
		return starlark.None, nil
	}
	symbol := p.symbols[index]
	return starfile.NewRecord(starlark.StringDict{"symbol": &pdbSymbolValue{symbol: symbol}, "displacement": starlark.MakeUint64(rva - uint64(symbol.rva))}), nil
}
