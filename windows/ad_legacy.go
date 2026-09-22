package windows

// Windows 2000 Active Directory persisted security records. These are the
// revision-2 PEK/RC4 formats, not the AES formats used by newer controllers.

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"sort"

	"go.starlark.net/starlark"
)

func adRC4(data, key, salt []byte, rounds int) []byte {
	hash := md5.New()
	hash.Write(key)
	for i := 0; i < rounds; i++ {
		hash.Write(salt)
	}
	cipher, _ := rc4.NewCipher(hash.Sum(nil)) // MD5 always supplies a 16-byte key.
	output := make([]byte, len(data))
	cipher.XORKeyStream(output, data)
	return output
}

// ADStoredSID converts a wire-format SID to the directory's indexed form,
// which stores only the final subauthority (RID) in big-endian order.
func ADStoredSID(sid []byte) ([]byte, error) {
	if len(sid) < 12 || sid[0] != 1 || int(sid[1])*4+8 != len(sid) || sid[1] > 15 {
		return nil, fmt.Errorf("AD SID: invalid SID or missing RID")
	}
	data := append([]byte(nil), sid...)
	offset := len(data) - 4
	binary.BigEndian.PutUint32(data[offset:], binary.LittleEndian.Uint32(sid[offset:]))
	return data, nil
}

func adStoredSIDBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sid starlark.Bytes
	if err := starlark.UnpackArgs("ad_stored_sid", args, kwargs, "sid", &sid); err != nil {
		return nil, err
	}
	data, err := ADStoredSID([]byte(sid))
	return starlark.Bytes(data), err
}

func adAncestorsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tags *starlark.List
	if err := starlark.UnpackArgs("ad_ancestors", args, kwargs, "tags", &tags); err != nil {
		return nil, err
	}
	if tags.Len() == 0 || tags.Len() > 1024 {
		return nil, fmt.Errorf("AD ancestors: require 1..1024 tags")
	}
	data := make([]byte, tags.Len()*4)
	seen := make(map[uint32]bool)
	for i := 0; i < tags.Len(); i++ {
		var tag uint32
		if err := starlark.AsInt(tags.Index(i), &tag); err != nil {
			return nil, err
		}
		if tag == 0 || seen[tag] {
			return nil, fmt.Errorf("AD ancestors: zero or repeated tag %d", tag)
		}
		seen[tag] = true
		binary.LittleEndian.PutUint32(data[i*4:], tag)
	}
	return starlark.Bytes(data), nil
}

// ADLegacyDNBinary encodes a non-linked DN-Binary attribute as a DNT followed
// by a length-prefixed blob. The blob length includes its four-byte length.
// Windows 2000 ntdsa validates total == 4 + blobLength; wellKnownObjects lookup
// compares 16 bytes at offset 8 and returns the DNT at offset 0.
func ADLegacyDNBinary(tag uint32, value []byte) ([]byte, error) {
	if tag == 0 || len(value) > 16<<20 {
		return nil, fmt.Errorf("AD DN-Binary: invalid tag or oversized value")
	}
	data := make([]byte, 8+len(value))
	binary.LittleEndian.PutUint32(data, tag)
	binary.LittleEndian.PutUint32(data[4:], uint32(4+len(value)))
	copy(data[8:], value)
	return data, nil
}

func adLegacyDNBinaryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tag uint32
	var value starlark.Bytes
	if err := starlark.UnpackArgs("ad_legacy_dn_binary", args, kwargs, "tag", &tag, "value", &value); err != nil {
		return nil, err
	}
	data, err := ADLegacyDNBinary(tag, []byte(value))
	return starlark.Bytes(data), err
}

// ADReplicationSchedule encodes SCHEDULE_INTERVAL: 168 hourly bytes, each
// containing four quarter-hour availability bits, starting Sunday at 00:00 UTC.
func ADReplicationSchedule(hours []byte) ([]byte, error) {
	if len(hours) != 168 {
		return nil, fmt.Errorf("AD schedule: require 168 hourly values")
	}
	for _, hour := range hours {
		if hour&0xf0 != 0 {
			return nil, fmt.Errorf("AD schedule: reserved hourly bits set")
		}
	}
	data := make([]byte, 188)
	binary.LittleEndian.PutUint32(data, 188)
	binary.LittleEndian.PutUint32(data[8:], 1)
	binary.LittleEndian.PutUint32(data[16:], 20)
	copy(data[20:], hours)
	return data, nil
}

func adReplicationScheduleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var hours starlark.Bytes
	if err := starlark.UnpackArgs("ad_replication_schedule", args, kwargs, "hours", &hours); err != nil {
		return nil, err
	}
	data, err := ADReplicationSchedule([]byte(hours))
	return starlark.Bytes(data), err
}

// ADLegacyPEKList builds an encrypted revision-2 password encryption key list
// containing key zero. generated is a Windows FILETIME. All keys and the salt
// must contain exactly 16 bytes; callers supply entropy explicitly.
func ADLegacyPEKList(bootKey, key, salt []byte, generated uint64) ([]byte, error) {
	if len(bootKey) != 16 || len(key) != 16 || len(salt) != 16 {
		return nil, fmt.Errorf("AD PEK list: boot key, key and salt must each contain 16 bytes")
	}
	plain := make([]byte, 52)
	copy(plain, []byte{0x56, 0xd9, 0x81, 0x48, 0xec, 0x91, 0xd1, 0x11, 0x90, 0x5a, 0x00, 0xc0, 0x4f, 0xc2, 0xd4, 0xcf})
	binary.LittleEndian.PutUint64(plain[16:], generated)
	binary.LittleEndian.PutUint32(plain[28:], 1)
	copy(plain[36:], key)
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header, 2)
	binary.LittleEndian.PutUint32(header[4:], 1)
	copy(header[8:], salt)
	return append(header, adRC4(plain, bootKey, salt, 1000)...), nil
}

// ADLegacySecret encrypts a directory secret with PEK zero. Password hashes
// must already have their RID-based DES protection before this outer layer.
func ADLegacySecret(secret, key, salt []byte) ([]byte, error) {
	if len(key) != 16 || len(salt) != 16 || len(secret) == 0 {
		return nil, fmt.Errorf("AD secret: require a nonempty secret and 16-byte key and salt")
	}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint16(header, 0x11)
	copy(header[8:], salt)
	return append(header, adRC4(secret, key, salt, 1)...), nil
}

// ADReplicationMetadata constructs initial version-one attribute metadata.
// invocationID is a GUID in Windows byte order. changed uses the target
// directory generation's persisted time representation; the Windows 2000
// bootstrap uses UTC seconds since 1970. Origin and local USNs both equal usn.
func ADReplicationMetadata(attributes []uint32, invocationID []byte, changed, usn uint64) ([]byte, error) {
	if len(invocationID) != 16 {
		return nil, fmt.Errorf("AD replication metadata: invocation ID must contain 16 bytes")
	}
	ids := append([]uint32(nil), attributes...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return nil, fmt.Errorf("AD replication metadata: duplicate attribute %d", ids[i])
		}
	}
	data := make([]byte, 16+48*len(ids))
	binary.LittleEndian.PutUint64(data, 1)
	binary.LittleEndian.PutUint64(data[8:], uint64(len(ids)))
	for i, id := range ids {
		entry := data[16+48*i:]
		binary.LittleEndian.PutUint32(entry, id)
		binary.LittleEndian.PutUint32(entry[4:], 1)
		binary.LittleEndian.PutUint64(entry[8:], changed)
		copy(entry[16:], invocationID)
		binary.LittleEndian.PutUint64(entry[32:], usn)
		binary.LittleEndian.PutUint64(entry[40:], usn)
	}
	return data, nil
}

func adLegacyPEKListBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var boot, key, salt starlark.Bytes
	var generated uint64
	if err := starlark.UnpackArgs("ad_legacy_pek_list", args, kwargs, "boot_key", &boot, "key", &key, "salt", &salt, "generated", &generated); err != nil {
		return nil, err
	}
	data, err := ADLegacyPEKList([]byte(boot), []byte(key), []byte(salt), generated)
	return starlark.Bytes(data), err
}

func adLegacySecretBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var secret, key, salt starlark.Bytes
	if err := starlark.UnpackArgs("ad_legacy_secret", args, kwargs, "secret", &secret, "key", &key, "salt", &salt); err != nil {
		return nil, err
	}
	data, err := ADLegacySecret([]byte(secret), []byte(key), []byte(salt))
	return starlark.Bytes(data), err
}

func adReplicationMetadataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var attributes *starlark.List
	var invocation starlark.Bytes
	var changed, usn uint64
	if err := starlark.UnpackArgs("ad_replication_metadata", args, kwargs, "attributes", &attributes, "invocation_id", &invocation, "changed", &changed, "usn", &usn); err != nil {
		return nil, err
	}
	ids := make([]uint32, attributes.Len())
	for i := range ids {
		if err := starlark.AsInt(attributes.Index(i), &ids[i]); err != nil {
			return nil, fmt.Errorf("AD replication attribute %d: %w", i, err)
		}
	}
	data, err := ADReplicationMetadata(ids, []byte(invocation), changed, usn)
	return starlark.Bytes(data), err
}
