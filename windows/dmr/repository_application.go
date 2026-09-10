package dmr

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

// RepositoryApplication contains the Application entity fields consumed by the
// Windows 11 26100 DMR writer. These are original manifest/repository strings;
// resolved resource references belong to the separate RESA sections.
type RepositoryApplication struct {
	ApplicationUserModelID string
	DisplayName            string
	Description            string
	Square150x150Logo      string
	Square44x44Logo        string
	StartPage              string
	ForegroundText         string
	BackgroundColor        uint32
	ContentURIRules        []ContentURIRule
}

// ApplicationFromRepository applies the native Add_Application field mapping.
// capabilities is the package's legacy Capabilities mask. sourceFlag preserves
// the producer's separately supplied byte at wire offset 6: the root-package
// application pass uses 0, while a subsequent related-package pass uses 1.
// Selecting those packages and resolving the AUMID are caller responsibilities.
func ApplicationFromRepository(row RepositoryApplication, capabilities uint32, sourceFlag uint8) (Application, error) {
	app := Application{
		Value6: sourceFlag, Value7: uint8((capabilities >> 7) & 1),
		Value24: row.BackgroundColor,
		Strings: [6]string{row.ApplicationUserModelID, row.DisplayName, row.Description,
			row.Square150x150Logo, row.Square44x44Logo, row.StartPage},
		ContentURIRules: row.ContentURIRules,
	}
	for _, value := range app.Strings {
		if _, err := identityString(value); err != nil {
			return Application{}, err
		}
	}
	separator := strings.IndexByte(row.ApplicationUserModelID, '!')
	if separator <= 0 || separator == len(row.ApplicationUserModelID)-1 {
		return Application{}, fmt.Errorf("dmr: application requires a resolved family!application AUMID")
	}
	// Native wcschr('!') pointer arithmetic includes the separator and stores
	// a byte offset, not a rune count or the application's string length.
	app.Value10 = uint16(2 * len(utf16.Encode([]rune(row.ApplicationUserModelID[:separator+1]))))
	switch row.ForegroundText {
	case "":
	case "light":
		app.ForegroundText = 1
	case "dark":
		app.ForegroundText = 2
	default:
		return Application{}, fmt.Errorf("dmr: invalid application ForegroundText %q", row.ForegroundText)
	}
	if _, err := EncodeContentURIRules(row.ContentURIRules); err != nil {
		return Application{}, err
	}
	return app, nil
}
