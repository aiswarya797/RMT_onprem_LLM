package main

import "testing"

func TestVersionFlagsAreStrict(t *testing.T) {
	for _, test := range []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"--json"}, true},
		{[]string{"--bogus"}, false},
		{[]string{"trailing"}, false},
	} {
		if got := onlyJSONFlags(test.args); got != test.want {
			t.Fatalf("onlyJSONFlags(%v)=%v want %v", test.args, got, test.want)
		}
	}
}
