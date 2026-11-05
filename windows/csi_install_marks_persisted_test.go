package windows

import (
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"testing"
)

func TestCSIInstallMarksPersistedBinding(t *testing.T) {
	fn := cbsInstallMarksFromProvider(func() ([]uup.CBSDeploymentAction, error) { return nil, nil })
	identity := starlark.Bytes("A, Culture=neutral, Version=1.0.0.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64")
	entry := starlark.NewDict(3)
	entry.SetKey(starlark.String("identity"), identity)
	entry.SetKey(starlark.String("installed_sources"), starlark.NewList(nil))
	entry.SetKey(starlark.String("persisted_members"), starlark.NewList([]starlark.Value{identity}))
	input := starlark.Tuple{starlark.NewList([]starlark.Value{entry})}
	result, err := starlark.Call(&starlark.Thread{}, fn, input, nil)
	if err != nil || result.(*starlark.List).Len() != 1 {
		t.Fatalf("%v %v", result, err)
	}
	entry.SetKey(starlark.String("composition"), starlark.NewList(nil))
	if _, err = starlark.Call(&starlark.Thread{}, fn, input, nil); err == nil {
		t.Fatal("accepted conflicting inventory forms")
	}
}
