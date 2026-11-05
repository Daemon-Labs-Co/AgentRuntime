// Package protocol defines the worker protocol shared by the CommonRoom
// controller and the container runtime. It is extracted from the controller's
// existing worker entry point; names, versions and wire shapes are unchanged.
package protocol

import (
	"encoding/hex"
	"regexp"
	"strings"
)

// Worker actions. One invocation is one short-lived process: an action and at
// most one value operand.
const (
	ActionReady            = "ready-v1"
	ActionVerify           = "verify-v1"
	ActionStatus           = "status-v1"
	ActionJobs             = "jobs-v2"
	ActionIdle             = "idle-v1"
	ActionRun              = "run-v2"
	ActionCancel           = "cancel-v2"
	ActionCancelPair       = "cancel-pair-v1"
	ActionCancelPairSpace  = "cancel-pair-workspace-v1"
	ActionAuditLink        = "audit-link-v1"
	ActionAuthLogin        = "auth-login-v1"
	ActionAuthStatus       = "auth-status-v1"
	ActionAuthLogout       = "auth-logout-v1"
	ReadyVersion           = 1
	LifecycleVersion       = 2
	MaxRunRequestChars     = 16384
	MaxFenceRequestChars   = 4096
	MaxCredentialFileBytes = 65536
	MaxConfigFileBytes     = 8192
	ReadyTimeoutSeconds    = 10
	configProviderCodex    = "codex"
	configProviderClaude   = "claude"
	credentialFileCodex    = "auth.json"
	credentialFileClaude   = ".credentials.json"
)

// Actions lists every action the controller may send, in a stable order.
var Actions = []string{
	ActionReady, ActionVerify, ActionStatus, ActionJobs, ActionIdle, ActionRun,
	ActionCancel, ActionCancelPair, ActionCancelPairSpace, ActionAuditLink,
	ActionAuthLogin, ActionAuthStatus, ActionAuthLogout,
}

// CredentialFiles maps each provider to the credential file the worker checks.
var CredentialFiles = map[string]string{
	configProviderCodex:  credentialFileCodex,
	configProviderClaude: credentialFileClaude,
}

// Ready is the successful result of the ready-v1 action.
type Ready struct {
	Version          int             `json:"version"`
	LifecycleVersion int             `json:"lifecycleVersion"`
	Configured       bool            `json:"configured"`
	RuntimeReady     bool            `json:"runtimeReady"`
	Credentials      map[string]bool `json:"credentials"`
}

var jobPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// ValidJobID reports whether v is a well-formed worker job identifier.
func ValidJobID(v string) bool { return jobPattern.MatchString(v) }

// ValidImage reports whether v names an image by immutable digest: either
// "sha256:<64 hex>" or "<name>@sha256:<64 hex>". Tags are never accepted.
func ValidImage(v string) bool {
	if strings.HasPrefix(v, "sha256:") && len(v) == 71 {
		_, err := hex.DecodeString(v[7:])
		return err == nil
	}
	parts := strings.Split(v, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) != 64 || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\n\r") {
		return false
	}
	_, err := hex.DecodeString(parts[1])
	return err == nil
}
