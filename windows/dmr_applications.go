package windows

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

func dmrGlobalizationBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var g dmr.Globalization
	if err := starlark.UnpackArgs("dmr_globalization", args, kwargs, "application_id", &g.ApplicationID,
		"utf8?", &g.UTF8, "windows_display_language?", &g.WindowsDisplayLanguage); err != nil {
		return nil, err
	}
	data, err := dmr.EncodeGlobalization(g)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func dmrApplicationsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rows *starlark.List
	var capabilities uint32
	var sourceFlag uint8
	if err := starlark.UnpackArgs("dmr_applications", args, kwargs, "applications", &rows, "capabilities", &capabilities, "source_flag", &sourceFlag); err != nil {
		return nil, err
	}
	if rows.Len() < 1 || rows.Len() > 100 {
		return nil, fmt.Errorf("dmr_applications: requires 1..100 applications")
	}
	apps := make([]dmr.Application, rows.Len())
	for i := range apps {
		d, ok := rows.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("dmr_applications: application %d requires a dictionary", i)
		}
		var row dmr.RepositoryApplication
		var rules *starlark.List
		if err := starlark.UnpackArgs("dmr_applications application", nil, d.Items(),
			"application_user_model_id", &row.ApplicationUserModelID,
			"display_name?", &row.DisplayName, "description?", &row.Description,
			"square150x150_logo?", &row.Square150x150Logo, "square44x44_logo?", &row.Square44x44Logo,
			"start_page?", &row.StartPage, "foreground_text?", &row.ForegroundText,
			"background_color?", &row.BackgroundColor, "content_uri_rules?", &rules); err != nil {
			return nil, err
		}
		if rules != nil {
			if rules.Len() > 65535 {
				return nil, fmt.Errorf("dmr_applications: too many content-URI rules")
			}
			row.ContentURIRules = make([]dmr.ContentURIRule, rules.Len())
			for j := range row.ContentURIRules {
				d, ok := rules.Index(j).(*starlark.Dict)
				if !ok {
					return nil, fmt.Errorf("dmr_applications: content-URI rule requires a dictionary")
				}
				r := &row.ContentURIRules[j]
				if err := starlark.UnpackArgs("dmr_applications content-URI rule", nil, d.Items(),
					"uri", &r.URI, "include", &r.Include, "runtime_access", &r.RuntimeAccess, "flag1", &r.Flag1); err != nil {
					return nil, err
				}
			}
		}
		var err error
		apps[i], err = dmr.ApplicationFromRepository(row, capabilities, sourceFlag)
		if err != nil {
			return nil, fmt.Errorf("dmr_applications: application %d: %w", i, err)
		}
	}
	data, err := dmr.EncodeApplications(apps)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}

func dmrPackageSecurityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var flags, capabilities uint32
	var inbox bool
	var sidValue starlark.Value
	if err := starlark.UnpackArgs("dmr_package_security", args, kwargs, "ari_flags", &flags,
		"package_sid", &sidValue, "is_inbox", &inbox, "capabilities", &capabilities); err != nil {
		return nil, err
	}
	if flags&3 != 0 {
		return starlark.None, nil
	}
	sidFile, ok := sidValue.(starfile.File)
	if !ok || sidFile.Size() < 8 || sidFile.Size() > 68 {
		return nil, fmt.Errorf("dmr_package_security: requires a binary package SID of at most 68 bytes")
	}
	sid, err := starfile.ReadAll(sidFile)
	if err != nil {
		return nil, err
	}
	data, err := dmr.EncodeRepositorySecurity(flags, sid, inbox, capabilities)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}
