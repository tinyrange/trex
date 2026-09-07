package windows

// ReactOS uses split SAM values, unlike the offset-based Windows V/C records.
// These fixed records deliberately name every field (including ABI padding).
// No machine-specific record or registry template is used.
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	scriptvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

const ReactOSRecordRevision = 1

type ReactOSDomainRecord struct {
	Revision                     uint32 `json:"revision"`
	Reserved                     uint32 `json:"reserved"`
	CreationTime                 int64  `json:"creation_time"`
	ModifiedCount                int64  `json:"modified_count"`
	MaximumPasswordAge           int64  `json:"maximum_password_age"`
	MinimumPasswordAge           int64  `json:"minimum_password_age"`
	ForceLogoff                  int64  `json:"force_logoff"`
	LockoutDuration              int64  `json:"lockout_duration"`
	LockoutObservationWindow     int64  `json:"lockout_observation_window"`
	ModifiedCountAtLastPromotion int64  `json:"modified_count_at_last_promotion"`
	NextRID                      uint32 `json:"next_rid"`
	PasswordProperties           uint32 `json:"password_properties"`
	MinimumPasswordLength        uint16 `json:"minimum_password_length"`
	PasswordHistoryLength        uint16 `json:"password_history_length"`
	LockoutThreshold             uint16 `json:"lockout_threshold"`
	Alignment                    uint16 `json:"alignment"`
	ServerState                  uint32 `json:"server_state"`
	ServerRole                   uint32 `json:"server_role"`
	UASCompatibilityRequired     uint32 `json:"uas_compatibility_required"`
	TailPadding                  uint32 `json:"tail_padding"`
}

type ReactOSUserRecord struct {
	Revision         uint32 `json:"revision"`
	Reserved         uint32 `json:"reserved"`
	LastLogon        int64  `json:"last_logon"`
	LastLogoff       int64  `json:"last_logoff"`
	PasswordLastSet  int64  `json:"password_last_set"`
	AccountExpires   int64  `json:"account_expires"`
	LastBadPassword  int64  `json:"last_bad_password"`
	RID              uint32 `json:"rid"`
	PrimaryGroupRID  uint32 `json:"primary_group_rid"`
	AccountControl   uint32 `json:"account_control"`
	CountryCode      uint16 `json:"country_code"`
	CodePage         uint16 `json:"code_page"`
	BadPasswordCount uint16 `json:"bad_password_count"`
	LogonCount       uint16 `json:"logon_count"`
	AdminCount       uint16 `json:"admin_count"`
	OperatorCount    uint16 `json:"operator_count"`
}

type ReactOSGroupRecord struct {
	Revision   uint32 `json:"revision"`
	Reserved   uint32 `json:"reserved"`
	RID        uint32 `json:"rid"`
	Attributes uint32 `json:"attributes"`
}

type ReactOSGroupMembership struct {
	RID        uint32 `json:"rid"`
	Attributes uint32 `json:"attributes"`
}

type ReactOSPrivilege struct {
	LUID       uint64 `json:"luid"`
	Attributes uint32 `json:"attributes"`
}

func reactOSBinary(record any) ([]byte, error) {
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, record); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// MarshalBinary serializes the native fixed domain layout, not a host struct.
func (r ReactOSDomainRecord) MarshalBinary() ([]byte, error) {
	if r.Revision != ReactOSRecordRevision || r.Reserved != 0 || r.Alignment != 0 || r.TailPadding != 0 {
		return nil, fmt.Errorf("invalid ReactOS domain revision or reserved fields")
	}
	if r.ServerState < 1 || r.ServerState > 2 || r.ServerRole < 2 || r.ServerRole > 3 || r.UASCompatibilityRequired > 1 {
		return nil, fmt.Errorf("invalid ReactOS domain state/role")
	}
	if r.MaximumPasswordAge > 0 || r.MinimumPasswordAge > 0 || r.LockoutDuration > 0 || r.LockoutObservationWindow > 0 {
		return nil, fmt.Errorf("SAM policy intervals must be non-positive relative NT times")
	}
	return reactOSBinary(r)
}

func (r ReactOSUserRecord) MarshalBinary() ([]byte, error) {
	if r.Revision != ReactOSRecordRevision || r.Reserved != 0 || r.RID == 0 || r.PrimaryGroupRID == 0 {
		return nil, fmt.Errorf("invalid ReactOS user revision, reserved field or RID")
	}
	return reactOSBinary(r)
}

func (r ReactOSGroupRecord) MarshalBinary() ([]byte, error) {
	if r.Revision != ReactOSRecordRevision || r.Reserved != 0 || r.RID == 0 {
		return nil, fmt.Errorf("invalid ReactOS group revision, reserved field or RID")
	}
	return reactOSBinary(r)
}

// BuildReactOSRecord serializes one named record from a strict JSON object.
// This portable adapter is shared with Starlark; it performs no filesystem IO.
func BuildReactOSRecord(kind string, fields []byte) ([]byte, error) {
	decode := func(target any) error {
		trimmed := bytes.TrimSpace(fields)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return fmt.Errorf("ReactOS record fields must be an object")
		}
		d := json.NewDecoder(bytes.NewReader(fields))
		d.DisallowUnknownFields()
		if err := d.Decode(target); err != nil {
			return err
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			return fmt.Errorf("trailing data after ReactOS record fields")
		}
		return nil
	}
	switch kind {
	case "domain":
		r := ReactOSDomainRecord{Revision: ReactOSRecordRevision, ServerState: 1, ServerRole: 3}
		if err := decode(&r); err != nil {
			return nil, err
		}
		return r.MarshalBinary()
	case "user":
		r := ReactOSUserRecord{Revision: ReactOSRecordRevision}
		if err := decode(&r); err != nil {
			return nil, err
		}
		return r.MarshalBinary()
	case "group":
		r := ReactOSGroupRecord{Revision: ReactOSRecordRevision}
		if err := decode(&r); err != nil {
			return nil, err
		}
		return r.MarshalBinary()
	case "group_memberships":
		var r struct {
			Groups []ReactOSGroupMembership `json:"groups"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		return reactOSBinary(r.Groups)
	case "policy_string":
		var r struct {
			Value string `json:"value"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		data := utf16Bytes(r.Value)
		if len(data) > 65532 {
			return nil, fmt.Errorf("LSA string exceeds USHORT length")
		}
		header, _ := reactOSBinary(struct {
			Length, MaximumLength uint16
			BufferOffset          uint32
		}{uint16(len(data)), uint16(len(data) + 2), 8})
		return append(append(header, data...), 0, 0), nil
	case "policy_modification":
		var r struct {
			ModifiedCount int64 `json:"modified_count"`
			CreationTime  int64 `json:"creation_time"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		return reactOSBinary(r)
	case "policy_quota":
		var r struct {
			PagedPool         uint32 `json:"paged_pool"`
			NonPagedPool      uint32 `json:"non_paged_pool"`
			MinimumWorkingSet uint32 `json:"minimum_working_set"`
			MaximumWorkingSet uint32 `json:"maximum_working_set"`
			Pagefile          uint32 `json:"pagefile"`
			Alignment         uint32 `json:"alignment"`
			TimeLimit         int64  `json:"time_limit"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		if r.Alignment != 0 {
			return nil, fmt.Errorf("quota alignment must be zero")
		}
		return reactOSBinary(r)
	case "policy_audit":
		var r struct {
			Enabled bool     `json:"enabled"`
			Options []uint32 `json:"options"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		const auditCategoryCount = 9
		if len(r.Options) != auditCategoryCount {
			return nil, fmt.Errorf("ReactOS audit policy needs %d categories", auditCategoryCount)
		}
		values := []uint32{0}
		if r.Enabled {
			values[0] = 1
		}
		for _, option := range r.Options {
			if option > 3 {
				return nil, fmt.Errorf("invalid audit option")
			}
			values = append(values, option)
		}
		return reactOSBinary(append(values, auditCategoryCount))
	case "privileges":
		var r struct {
			Control    uint32             `json:"control"`
			Privileges []ReactOSPrivilege `json:"privileges"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		header, _ := reactOSBinary([]uint32{uint32(len(r.Privileges)), r.Control})
		data, err := reactOSBinary(r.Privileges)
		return append(header, data...), err
	case "logon_hours":
		var r struct {
			Allowed []bool `json:"allowed"`
		}
		if err := decode(&r); err != nil {
			return nil, err
		}
		const hoursPerWeek = 7 * 24
		if len(r.Allowed) != hoursPerWeek {
			return nil, fmt.Errorf("logon hours require %d hourly slots", hoursPerWeek)
		}
		data := make([]byte, 2+hoursPerWeek/8)
		binary.LittleEndian.PutUint16(data, hoursPerWeek)
		for i, allowed := range r.Allowed {
			if allowed {
				data[2+i/8] |= 1 << (i % 8)
			}
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unknown ReactOS record kind %q", kind)
	}
}

func reactOSRecordBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind string
	var fields *starlark.Dict
	if err := starlark.UnpackArgs("reactos_record", args, kwargs, "kind", &kind, "fields", &fields); err != nil {
		return nil, err
	}
	native, err := scriptvalue.Native(fields)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(native)
	if err != nil {
		return nil, err
	}
	data, err := BuildReactOSRecord(kind, encoded)
	if err != nil {
		return nil, fmt.Errorf("reactos_record(%s): %w", kind, err)
	}
	return starlark.Bytes(data), nil
}
