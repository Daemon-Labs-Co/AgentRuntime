//go:build linux || darwin

// Actual byte verification requires the approved private custody store.
package artifactmanifest

import (
	"commonroom-runtime/internal/objectcustody"
	"commonroom-runtime/internal/taskcontract"
	"context"
	"reflect"
)

// Resolve preflights the ENTIRE finite claim set before any object read. Actual
// byte integrity, authorization and audit acknowledgment remain mandatory.
func Resolve(ctx context.Context, definition taskcontract.Definition, scope objectcustody.ExecutionScope, outputName string, claims []Claim, store *objectcustody.Store) (Manifest, error) {
	if ctx == nil || ctx.Err() != nil || store == nil {
		return Manifest{}, ErrRefused
	}
	result, err := metadata(definition, scope, outputName, claims)
	if err != nil {
		return Manifest{}, ErrRefused
	}
	formats := map[string]format{}
	for _, file := range result.Files {
		formats[file.Name] = format{file.MediaType, file.StructuralCheck}
	}
	for _, claim := range claims {
		raw, err := store.Get(ctx, claim.Receipt.Intent.Scope, claim.Receipt)
		if err != nil || ctx.Err() != nil || !validFormatBytes(formats[claim.Name], raw) {
			return Manifest{}, ErrRefused
		}
	}
	if ctx.Err() != nil {
		return Manifest{}, ErrRefused
	}
	return result, nil
}

// Revalidate repeats actual byte checks after exact metadata preflight. Canonical
// digests alone never authorize delivery or certify observed execution checks.
func Revalidate(ctx context.Context, definition taskcontract.Definition, scope objectcustody.ExecutionScope, outputName string, claimed Manifest, store *objectcustody.Store) error {
	if ValidateMetadata(definition, scope, outputName, claimed) != nil {
		return ErrRefused
	}
	claims := make([]Claim, len(claimed.Files))
	for i, file := range claimed.Files {
		claims[i] = Claim{Name: file.Name, Receipt: file.Receipt}
	}
	actual, err := Resolve(ctx, definition, scope, outputName, claims, store)
	if err != nil || !reflect.DeepEqual(actual, claimed) {
		return ErrRefused
	}
	return nil
}
