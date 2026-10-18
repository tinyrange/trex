package cc

func storageDevicePath(nvme bool) []byte {
	path := []byte{2, 1, 12, 0, 0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0, 1, 1, 6, 0, 0, 1}
	if nvme {
		// NVMe namespace messaging node: NSID 1, no EUI-64 assigned.
		return append(path, 3, 0x17, 16, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	return append(path, 3, 1, 8, 0, 0, 0, 0, 0)
}
