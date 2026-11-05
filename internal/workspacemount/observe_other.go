//go:build !linux

package workspacemount

import "context"

// Unsupported platforms refuse; there is no host or simulated fallback.
func Observe(context.Context, string) (Proof, error) { return Proof{}, ErrRefused }

// ObserveObjects also refuses outside Linux; no simulated/host fallback.
func ObserveObjects(context.Context, string) (Proof, error) { return Proof{}, ErrRefused }
