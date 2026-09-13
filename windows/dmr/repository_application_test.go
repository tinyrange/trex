package dmr

import (
	"reflect"
	"strings"
	"testing"
)

func TestApplicationFromRepository(t *testing.T) {
	row := RepositoryApplication{
		ApplicationUserModelID: "Example_pub!App", DisplayName: "ms-resource:Name",
		Description: "Description", Square150x150Logo: "Assets/large.png",
		Square44x44Logo: "Assets/small.png", StartPage: "https://example.test/",
		ForegroundText: "light", BackgroundColor: 0x11223344,
	}
	app, err := ApplicationFromRepository(row, 0x80, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeApplications([]Application{app})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseApplications(encoded)
	if err != nil || len(got) != 1 {
		t.Fatalf("parse: %v", err)
	}
	want := Application{Value6: 0, Value7: 1, Value10: 24, ForegroundText: 1, Value24: 0x11223344,
		Strings: [6]string{"Example_pub!App", "ms-resource:Name", "Description", "Assets/large.png", "Assets/small.png", "https://example.test/"}}
	// Content-URI parsing returns an empty slice when no rules are present.
	got[0].ContentURIRules = nil
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("application: %+v", got[0])
	}
	for text, value := range map[string]uint32{"": 0, "light": 1, "dark": 2} {
		row.ForegroundText = text
		app, err = ApplicationFromRepository(row, ^uint32(0x80), 1)
		if err != nil || app.ForegroundText != value || app.Value7 != 0 || app.Value6 != 1 {
			t.Fatalf("foreground %q: %+v %v", text, app, err)
		}
	}
	row.ForegroundText = ""
	row.ApplicationUserModelID = "F\U0001f600!App"
	app, err = ApplicationFromRepository(row, 0, 0)
	if err != nil || app.Value10 != 8 {
		t.Fatalf("UTF-16 byte offset: %+v %v", app, err)
	}
	for _, aumid := range []string{"", "Family", "!App", "Family!", "Family\x00!App", "\xff!App", strings.Repeat("x", 32766) + "!A"} {
		row.ApplicationUserModelID = aumid
		if _, err := ApplicationFromRepository(row, 0, 0); err == nil {
			t.Fatalf("accepted invalid AUMID of length %d", len(aumid))
		}
	}
	row.ApplicationUserModelID = "Family!App"
	for _, text := range []string{"Light", "DARK", "transparent", "light\x00"} {
		row.ForegroundText = text
		if _, err := ApplicationFromRepository(row, 0, 0); err == nil {
			t.Fatalf("accepted ForegroundText %q", text)
		}
	}
}
