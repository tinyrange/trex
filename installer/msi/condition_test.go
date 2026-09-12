package msi

import (
	"strings"
	"testing"
)

func TestConditions(t *testing.T) {
	values := map[string]string{"VersionNT": "501", "Name": "Platform SDK", "Zero": "0", "$Core": "3", "%PATH": "C:\\bin"}
	for _, tc := range []struct {
		expression string
		want       bool
	}{
		{"", true}, {"NOT Installed AND VersionNT >= 500", true}, {"1 OR 0 AND 0", true},
		{`Name ~>< "sdk"`, true}, {`Name << "Platform"`, true}, {`Name >> "SDK"`, true},
		{"Zero", true}, {`"bad" = 0`, false}, {`"bad" <> 0`, true}, {"$Core = 3", true},
		{"65538 << 1", true}, {"65538 >> 2", true}, {"3 >< 2", true},
		{"0 IMP 0", true}, {"1 EQV 0", false}, {"1 XOR 1", false},
		{`%Path = "C:\bin"`, true}, {"NOT (0 OR 1)", false},
	} {
		got, err := EvaluateCondition(tc.expression, values)
		if err != nil || got != tc.want {
			t.Errorf("%q = %v, %v; want %v", tc.expression, got, err, tc.want)
		}
	}
	for _, expression := range []string{`"open`, "(1", "1 AND", "$Missing=3", "1 === 2", strings.Repeat("NOT ", 1025) + "1"} {
		if _, err := EvaluateCondition(expression, values); err == nil {
			t.Errorf("accepted %q", expression)
		}
	}
}
