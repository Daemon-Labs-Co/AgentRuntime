package workspacecapture

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/workspacesnapshot"
	"context"
	"errors"
	"os"
)

// Request is supervisor-owned finite output metadata, never a model-selected
// source root or proof of authorization. Capture computes its actual revision.
type Request struct {
	Binding   workspacesnapshot.Binding  `json:"binding"`
	Members   []workspacesnapshot.Member `json:"members"`
	Challenge string                     `json:"challenge"`
}

// CapturedObjects is returned only after every declared selected member is sealed
// and the complete source is still current. It is not human acceptance, public
// release authority or an atomic storage transaction: failures retain partial data.
type CapturedObjects struct {
	Snapshot workspacesnapshot.Snapshot
	Receipts []objectcustody.Receipt
}

// CaptureToCustody transfers a fixed isolated source into an independently private
// quota-backed object root. Journal MUST durably reserve and physically enforce
// exact object quota before writes; it must independently validate source/seal and
// current authority. Neither this adapter nor directory permissions supply quota.
// There is no host source path, release operation, automatic retry/refund/deletion
// or permissive journal. The caller owns the object root throughout the call.
func CaptureToCustody(ctx context.Context, request Request, authority Authority, objectRoot *os.Root, journal objectcustody.Journal) (CapturedObjects, error) {
	return captureToCustody(ctx, fixedContainerView{}, request, authority, objectRoot, journal)
}
func captureToCustody(ctx context.Context, view containerView, request Request, authority Authority, objectRoot *os.Root, journal objectcustody.Journal) (CapturedObjects, error) {
	var result CapturedObjects
	attempted := false
	if ctx == nil || ctx.Err() != nil || objectRoot == nil || missingJournal(journal) {
		return result, ErrRefused
	}
	ctx, cancel := context.WithTimeout(ctx, MaxLifetime)
	defer cancel()
	err := withFrozenSource(ctx, view, request.Binding, request.Members, request.Challenge, authority, func(source *workspacesnapshot.Source) error {
		// This decorator binds storage intent/seal to actual captured bytes before the
		// external journal can acknowledge them. Its private store cannot release data.
		bound := &capturedSourceJournal{source: source, journal: journal}
		store, err := objectcustody.New(objectRoot, bound)
		if err != nil {
			return err
		}
		snapshot := source.Snapshot()
		receipts := make([]objectcustody.Receipt, 0, len(snapshot.Members))
		for _, member := range snapshot.Members {
			scope := objectcustody.Scope{ExecutionScope: snapshot.Scope, OutputName: member.OutputName, MemberName: member.Name}
			reader, err := source.Open(ctx, scope, member.MaxBytes)
			if err != nil {
				return err
			}
			attempted = true
			receipt, putErr := store.Put(ctx, scope, member.MaxBytes, reader)
			closeErr := reader.Close()
			if putErr != nil || closeErr != nil {
				return errors.Join(objectcustody.ErrUnconfirmed, putErr, closeErr)
			}
			if source.VerifyReceipt(ctx, receipt) != nil {
				return objectcustody.ErrUnconfirmed
			}
			receipts = append(receipts, receipt)
		}
		if source.Current(ctx) != nil {
			return objectcustody.ErrUnconfirmed
		}
		result = CapturedObjects{Snapshot: snapshot, Receipts: receipts}
		return nil
	})
	if err != nil {
		if attempted {
			return CapturedObjects{}, errors.Join(objectcustody.ErrUnconfirmed, err)
		}
		return CapturedObjects{}, err
	}
	return result, nil
}
func missingJournal(j objectcustody.Journal) bool {
	// Use the same typed-nil treatment as mandatory source authority.
	return j == nil || isNilDependency(j)
}

type capturedSourceJournal struct {
	source  *workspacesnapshot.Source
	journal objectcustody.Journal
}

func (j *capturedSourceJournal) Reserve(ctx context.Context, intent objectcustody.Intent) error {
	snapshot := j.source.Snapshot()
	if !objectcustody.ValidIntent(intent) || intent.Scope.ExecutionScope != snapshot.Scope {
		return ErrRefused
	}
	memberFound := false
	for _, m := range snapshot.Members {
		if m.OutputName == intent.Scope.OutputName && m.Name == intent.Scope.MemberName && m.MaxBytes == intent.MaxBytes {
			memberFound = true
			break
		}
	}
	if !memberFound || j.source.Current(ctx) != nil {
		return ErrRefused
	}
	if err := j.journal.Reserve(ctx, intent); err != nil {
		return err
	}
	// Quota setup may revoke/change source authority. Refuse before object creation
	// or member streaming; retain any durable reservation rather than refunding it.
	if j.source.Current(ctx) != nil {
		return objectcustody.ErrUnconfirmed
	}
	return nil
}
func (j *capturedSourceJournal) Seal(ctx context.Context, receipt objectcustody.Receipt) error {
	if j.source.VerifyReceipt(ctx, receipt) != nil {
		return ErrRefused
	}
	return j.journal.Seal(ctx, receipt)
}
func (*capturedSourceJournal) AuthorizeRead(context.Context, objectcustody.Scope, objectcustody.Receipt) error {
	return ErrRefused
}
func (*capturedSourceJournal) AcknowledgeRead(context.Context, objectcustody.Receipt) error {
	return ErrRefused
}

var _ objectcustody.Journal = (*capturedSourceJournal)(nil)
