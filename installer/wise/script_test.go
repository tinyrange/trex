package wise

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestParseScriptInstallFile(t *testing.T) {
	data := make([]byte, 43)
	for _, value := range []string{"product", "company", "language"} {
		data = append(data, value...)
		data = append(data, 0)
	}
	data = append(data, make([]byte, 6)...)
	data = append(data, 1) // language count

	fixed := make([]byte, 42)
	binary.LittleEndian.PutUint32(fixed[2:6], 0)
	binary.LittleEndian.PutUint32(fixed[6:10], 1)
	binary.LittleEndian.PutUint32(fixed[14:18], 2)
	binary.LittleEndian.PutUint32(fixed[38:42], 0x12345678)
	data = append(data, 0x00)
	data = append(data, fixed...)
	for _, value := range []string{`%MAINDIR%\program.exe`, "Program file", "PROGRAM.EXE"} {
		data = append(data, value...)
		data = append(data, 0)
	}

	script, err := parseScript(&starfile.Bytes{Name: "WiseScript.bin", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if script.languageCount != 1 || len(script.actions) != 1 || len(script.files) != 1 {
		t.Fatalf("unexpected parsed script: languages=%d actions=%d files=%d", script.languageCount, len(script.actions), len(script.files))
	}
	file := script.files[0]
	if file.destination != `%MAINDIR%\program.exe` || file.source != "PROGRAM.EXE" || file.expanded != 2 || file.crc != 0x12345678 {
		t.Fatalf("unexpected file metadata: %#v", file)
	}
}

func TestExpandWiseVariables(t *testing.T) {
	variables := map[string]string{"MAINDIR": `C:\Program Files\Demo`, "EXE": "demo.exe"}
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{`%MAINDIR%\%EXE%`, `C:\Program Files\Demo\demo.exe`, true},
		{`command.exe %%1`, `command.exe %1`, true},
		{`%UNKNOWN%\file`, `%UNKNOWN%\file`, false},
	}
	for _, test := range tests {
		got, ok := expandWiseVariables(test.input, variables)
		if got != test.want || ok != test.ok {
			t.Errorf("expandWiseVariables(%q) = %q, %t; want %q, %t", test.input, got, ok, test.want, test.ok)
		}
	}
}
