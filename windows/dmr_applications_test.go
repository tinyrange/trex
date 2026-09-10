package windows

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

func TestDMRApplicationBuiltins(t *testing.T) {
	globals := Builtins()
	globals["sid"] = &starfile.Bytes{Data: []byte{1, 1, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0}}
	eval := func(expr string) (starlark.Value, error) {
		return starlark.Eval(&starlark.Thread{Name: "dmr-apps"}, "test.star", expr, globals)
	}
	value, err := eval(`dmr_applications([{"application_user_model_id":"Family!App","foreground_text":"dark","content_uri_rules":[{"uri":"https://example.test/","include":True,"runtime_access":2,"flag1":True}]}], capabilities=128, source_flag=0)`)
	if err != nil {
		t.Fatal(err)
	}
	globValue, err := eval(`dmr_globalization("Global.Taskbar",utf8=True,windows_display_language=True)`)
	if err != nil {
		t.Fatal(err)
	}
	glob, err := dmr.ParseGlobalization(globValue.(*starfile.Bytes).Data)
	if err != nil || glob.ApplicationID != "Global.Taskbar" || !glob.UTF8 || !glob.WindowsDisplayLanguage {
		t.Fatalf("globalization: %+v %v", glob, err)
	}
	apps, err := dmr.ParseApplications(value.(*starfile.Bytes).Data)
	if err != nil || len(apps) != 1 || apps[0].Value7 != 1 || apps[0].Value10 != 14 || apps[0].ForegroundText != 2 || len(apps[0].ContentURIRules) != 1 {
		t.Fatalf("applications: %+v %v", apps, err)
	}
	rule := apps[0].ContentURIRules[0]
	if !rule.Flag1 || !rule.Include || rule.RuntimeAccess != 2 || rule.URI != "https://example.test/" {
		t.Fatalf("rule: %+v", rule)
	}
	for _, extra := range []string{"", `,start_page=mrm_literal_reference("")`} {
		value, err = eval(`dmr_application_resources(33,mrm_index_reference(1),mrm_literal_reference(""),mrm_index_reference(2),mrm_literal_reference("C:/small.png")` + extra + `)`)
		if err != nil {
			t.Fatal(err)
		}
		r, err := dmr.ParseResources(value.(*starfile.Bytes).Data)
		count := 4
		if extra != "" {
			count++
		}
		if err != nil || !r.Application || r.Index != 33 || len(r.Entries) != count {
			t.Fatalf("RESA: %+v %v", r, err)
		}
	}
	value, err = eval(`dmr_package_security(ari_flags=0x110,package_sid=sid,is_inbox=True,capabilities=5)`)
	if err != nil {
		t.Fatal(err)
	}
	security, err := dmr.ParseSecurityContext(value.(*starfile.Bytes).Data)
	if err != nil || security.Flags != 1 || len(security.Capabilities) != 2 {
		t.Fatalf("security: %+v %v", security, err)
	}
	value, err = eval(`dmr_package_security(ari_flags=0x111,package_sid=None,is_inbox=True,capabilities=0)`)
	if err != nil || value != starlark.None {
		t.Fatalf("framework omission: %v %v", value, err)
	}
	for _, expr := range []string{
		`dmr_applications([],0,0)`, `dmr_applications([1],0,0)`,
		`dmr_applications([{}],0,0)`, `dmr_applications([{"application_user_model_id":"Family!App"}]*101,0,0)`,
		`dmr_applications([{"application_user_model_id":"Family!App"}],0,256)`,
		`dmr_applications([{"application_user_model_id":"Family!App","content_uri_rules":[1]}],0,0)`,
		`dmr_applications([{"application_user_model_id":"Family!App","content_uri_rules":[{"uri":"x","include":True,"runtime_access":3,"flag1":False}]}],0,0)`,
		`dmr_package_security(0x110,None,False,0)`,
		`dmr_package_security(0x110,"SID",False,0)`,
		`dmr_globalization("")`,
		`dmr_application_resources(0,None,None,None,None)`,
		`dmr_application_resources(641,mrm_literal_reference(""),mrm_literal_reference(""),mrm_literal_reference(""),mrm_literal_reference(""))`,
	} {
		if _, err := eval(expr); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
}
