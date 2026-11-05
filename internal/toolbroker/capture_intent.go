package toolbroker

import "commonroom-runtime/internal/workspacecapture"

// CaptureIntent is immutable finite lifecycle metadata, not source/quota/launch
// authority. Each use still requires current authenticated supervisor admission.
type CaptureIntent struct {
	Request workspacecapture.Request `json:"request"`
	Image   string                   `json:"image"`
	Objects CaptureObjectVolume      `json:"objects"`
}
