package lifecycle

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestPreviewCLIGatesBeforeOpeningInstallation(t *testing.T) {
	t.Setenv("LLM_MONITOR_EXPERIMENTAL", "")
	for _, args := range [][]string{{"setup", "master"}, {"setup", "collector"}, {"probe", "import"}, {"compare", "create"}, {"destinations", "create"}} {
		var out, err bytes.Buffer
		code := RunCLI(context.Background(), args, &out, &err, nil)
		if code != 2 || !strings.Contains(err.String(), "same-machine preview") {
			t.Fatalf("%v: %d %s", args, code, err.String())
		}
	}
}
