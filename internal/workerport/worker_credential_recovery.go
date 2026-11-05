package workerport

import (
	"errors"
	"os"
	"path/filepath"
)

const workerCredentialRecoveryName = ".credential-recovery-required"

// workerCredentialReady treats any marker, unreadable entry or malformed path as
// unresolved custody. Its contents are deliberately not needed to deny reuse.
// This is a mandatory worker security boundary, not an optional feature.
func workerCredentialReady(root string) bool {
	_, err := os.Lstat(filepath.Join(root, workerCredentialRecoveryName))
	return os.IsNotExist(err)
}

// markWorkerCredentialUncertain runs under the connection credential lock and
// durably blocks reuse BEFORE any bytes are supplied to an engine. Process exit,
// flock release and confirmed container absence cannot establish refreshed-token
// custody. No token, model output or customer data belongs in this marker.
func markWorkerCredentialUncertain(root string) error {
	return markWorkerCredentialUncertainDurably(root, syncParentDirectory)
}

func markWorkerCredentialUncertainDurably(root string, syncDirectory func(string) error) error {
	if err := replacePrivateDurably(filepath.Join(root, workerCredentialRecoveryName), []byte("{\"version\":1,\"recoveryRequired\":true}\n"), syncDirectory); err != nil {
		return errors.New("Connection credential recovery marker could not be persisted")
	}
	return nil
}

// clearWorkerCredentialRecovery is permitted only after a new login or local
// revocation has been durably committed under the lock, with execution quiescent.
// Removal durability errors remain errors; never acknowledge uncertain recovery.
func clearWorkerCredentialRecovery(root string, syncDirectory func(string) error) error {
	path := filepath.Join(root, workerCredentialRecoveryName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return errors.New("Connection credential recovery remains unresolved")
	}
	if err := syncDirectory(path); err != nil {
		return errors.New("Connection credential recovery durability unconfirmed")
	}
	return nil
}

// workerCredentialConnectionQuiescent permits explicit reauthentication after
// execution roles are fenced even while source is retained. Unknown or corrupt
// journal entries refuse recovery. A released flock alone is not shutdown proof.
func workerCredentialConnectionQuiescent(dir, connection, provider string) bool {
	records, err := boundedWorkerRecords(dir)
	if err != nil {
		return false
	}
	for _, record := range records {
		if !validWorkerRecord(record) {
			return false
		}
		if record.ConnectionID != connection || record.Provider != provider {
			continue
		}
		if record.Pair != nil {
			if !pairRoleSettled(record.Pair.Engine) || !pairRoleSettled(record.Pair.Tool) {
				return false
			}
		} else if !workerJobSettled(record) {
			return false
		}
	}
	return true
}
