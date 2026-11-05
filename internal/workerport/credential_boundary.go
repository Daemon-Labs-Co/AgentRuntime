package workerport

import "errors"

var errCredentialBoundary = errors.New("Development is unavailable until a verified credential-separated provider bridge is configured; native tools cannot share provider credentials")

// requireCredentialSeparatedDevelopment closes the legacy shared-credential
// execution path. A fork CAN remove it, BUT model-controlled native tools then
// regain readable provider credentials. No feature flag, owner role or paid
// entitlement may restore this unsafe fallback. Chat/login remain separate.
func requireCredentialSeparatedDevelopment(repository string) error {
	if repository != "" {
		return errCredentialBoundary
	}
	return nil
}
