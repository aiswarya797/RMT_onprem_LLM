package config

import "testing"

func TestExperimentalFeaturesRequireExplicitOptIn(t *testing.T) {
	for _, value := range []string{"", "0", "true", "1"} {
		t.Setenv("LLM_MONITOR_EXPERIMENTAL", value)
		if ExperimentalFeaturesEnabled() != (value == "1") {
			t.Fatalf("unexpected gate for %q", value)
		}
	}
}
