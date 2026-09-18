package config

import "os"

// ExperimentalFeaturesEnabled keeps unqualified workflows out of the local
// preview. It never deletes their implementation, configuration or history.
func ExperimentalFeaturesEnabled() bool {
	return os.Getenv("LLM_MONITOR_EXPERIMENTAL") == "1"
}

const ExperimentalMessage = "This workflow is not available in the same-machine preview. Developers can opt in with LLM_MONITOR_EXPERIMENTAL=1; see docs/experimental.md."
