package msi

import (
	"go.starlark.net/starlark"
	"maps"
	"strings"
)

// effectPlans retains the standard action's input records and resolves its
// formatted fields. These records are execution requests, not a claim that
// running code (self-registration, services, ODBC) has already taken effect.
func (p *planContext) effectPlans() []starlark.Value {
	type handler struct {
		table, operation string
		formatted        []string
	}
	handlers := []handler{
		{"Shortcut", "create_shortcut", []string{"Arguments", "Description"}},
		{"Environment", "edit_environment", []string{"Name", "Value"}},
		{"IniFile", "edit_ini", []string{"Section", "Key", "Value"}},
		{"RemoveIniFile", "remove_ini", []string{"Section", "Key", "Value"}},
		{"RemoveRegistry", "remove_registry", []string{"Key", "Name"}},
		{"RemoveFile", "remove_file", nil},
		{"DuplicateFile", "duplicate_file", nil},
		{"MoveFile", "move_file", nil},
		{"Class", "register_class", []string{"Argument"}},
		{"ProgId", "register_progid", nil},
		{"TypeLib", "register_type_library", nil},
		{"SelfReg", "self_register", nil},
		{"Extension", "register_extension", nil},
		{"MIME", "register_mime", nil},
		{"Verb", "register_verb", []string{"Command", "Argument"}},
		{"ServiceInstall", "install_service", []string{"Name", "DisplayName", "LoadOrderGroup", "Dependencies", "StartName", "Password", "Arguments", "Description"}},
		{"ServiceControl", "control_service", []string{"Name", "Arguments"}},
		{"ODBCDriver", "install_odbc_driver", nil},
		{"ODBCDataSource", "install_odbc_data_source", nil},
		{"ODBCTranslator", "install_odbc_translator", nil},
		{"PublishComponent", "publish_component", []string{"AppData"}},
		{"MsiAssembly", "install_assembly", nil},
		{"LockPermissions", "set_permissions", []string{"Domain", "User"}},
	}
	result := []starlark.Value{}
	for _, h := range handlers {
		for index, row := range p.db.Tables[h.table] {
			if component := text(row, "Component_"); component != "" && !p.selected[component] {
				continue
			}
			if h.table == "RemoveFile" && integer(row, "InstallMode")&1 == 0 {
				continue
			}
			if h.table == "SelfReg" {
				file := text(row, "File_")
				selected := false
				for _, f := range p.db.Tables["File"] {
					if text(f, "File") == file {
						selected = p.selected[text(f, "Component_")]
						break
					}
				}
				if !selected {
					continue
				}
			}
			expanded := maps.Clone(row)
			for _, name := range h.formatted {
				if row[name] != nil && row[name] != starlark.None {
					expanded[name] = starlark.String(p.format(text(row, name)))
				}
			}
			fields := map[string]starlark.Value{"operation": starlark.String(h.operation), "fields": record(expanded), "provenance": record(map[string]starlark.Value{"table": starlark.String(h.table), "row": starlark.MakeInt(index)}), "requires_execution": starlark.True}
			switch h.table {
			case "Shortcut":
				fields["path"] = starlark.String(winJoin(p.directories[text(row, "Directory_")], longName(text(row, "Name"))+".lnk"))
				target := text(row, "Target")
				if strings.Contains(target, "[") {
					fields["target"] = starlark.String(p.format(target))
					fields["advertised"] = starlark.False
				} else {
					fields["feature"] = starlark.String(target)
					fields["advertised"] = starlark.True
				}
				fields["working_directory"] = starlark.String(p.directories[text(row, "WkDir")])
			case "IniFile", "RemoveIniFile":
				directory := p.properties[text(row, "DirProperty")]
				if directory == "" {
					directory = p.directories[text(row, "DirProperty")]
				}
				if text(row, "DirProperty") == "" {
					directory = p.properties["WindowsFolder"]
				}
				fields["path"] = starlark.String(winJoin(directory, longName(text(row, "FileName"))))
			case "RemoveFile":
				directory := p.properties[text(row, "DirProperty")]
				if directory == "" {
					directory = p.directories[text(row, "DirProperty")]
				}
				fields["directory"] = starlark.String(directory)
				fields["pattern"] = row["FileName"]
			case "DuplicateFile":
				fields["source_path"] = starlark.String(p.filePaths[text(row, "File_")])
				directory := p.directories[text(row, "DestFolder")]
				if directory == "" {
					directory = p.properties[text(row, "DestFolder")]
				}
				fields["directory"] = starlark.String(directory)
			case "SelfReg":
				fields["path"] = starlark.String(p.filePaths[text(row, "File_")])
			case "Environment":
				name := p.format(text(row, "Name"))
				flags := ""
				// Prefix characters independently specify install/uninstall and scope.
				end := 0
				for end < len(name) && strings.ContainsRune("=+-!*", rune(name[end])) {
					end++
				}
				flags = name[:end]
				fields["name"] = starlark.String(name[end:])
				fields["flags"] = starlark.String(flags)
				fields["machine"] = starlark.Bool(strings.Contains(flags, "*"))
			}
			result = append(result, record(fields))
		}
	}
	// Other product-defined tables can be consumed by custom actions. Preserve
	// them in Database.table; do not invent effects from their names.
	return result
}
