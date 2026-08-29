package starlarkfrontend

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	original, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir("../.."); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.Chdir(original)
	os.Exit(code)
}
