// Package workspacemount observes fixed isolated Linux workspace/custody mounts. Its
// report is not authentication, a source root, writer fencing or FrozenLease.
// Callers MUST bind the reviewed helper/container and hold creator ownership.
// A fork CAN run the helper on a host, BUT invalidates managed isolation claims.
package workspacemount

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const MaxMountInfoBytes = 256 * 1024

var ErrRefused = errors.New("read-only workspace mount observation refused")

type Proof struct {
	Version      int    `json:"version"`
	Challenge    string `json:"challenge"`
	MountID      int    `json:"mountId"`
	ReadOnly     bool   `json:"readOnly"`
	RootReadOnly bool   `json:"rootReadOnly"`
}

func ValidChallenge(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
}
func ValidProof(p Proof, challenge string) bool {
	return ValidChallenge(challenge) && p.Version == 1 && p.Challenge == challenge && p.MountID > 0 && p.ReadOnly && p.RootReadOnly
}

// mountID accepts only one explicit read-only workspace mount and no submounts.
// Unicode/path escapes in mountinfo are not needed for this fixed path; decode
// kernel octal escapes before checking for workspace descendants.
func mountID(raw []byte) (int, error) { return mountIDAt(raw, "/workspace") }

func mountIDAt(raw []byte, root string) (int, error) {
	if root != "/workspace" && root != "/objects" {
		return 0, ErrRefused
	}
	if len(raw) == 0 || len(raw) > MaxMountInfoBytes {
		return 0, ErrRefused
	}
	id := 0
	ids := map[int]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, v := range f {
			if v == "-" {
				if sep != -1 {
					return 0, ErrRefused
				}
				sep = i
			}
		}
		if len(f) < 10 || sep < 6 || sep+4 != len(f) {
			return 0, ErrRefused
		}
		n, e := strconv.Atoi(f[0])
		parent, e2 := strconv.Atoi(f[1])
		if e != nil || e2 != nil || n <= 0 || parent < 0 || ids[n] {
			return 0, ErrRefused
		}
		ids[n] = true
		mounted, ok := mountPath(f[4])
		if !ok {
			return 0, ErrRefused
		}
		if strings.HasPrefix(mounted, root+"/") {
			return 0, ErrRefused
		}
		if mounted != root {
			continue
		}
		if id != 0 {
			return 0, ErrRefused
		}
		ro, rw := false, false
		for _, option := range strings.Split(f[5], ",") {
			if option == "ro" {
				ro = true
			}
			if option == "rw" {
				rw = true
			}
		}
		if !ro || rw {
			return 0, ErrRefused
		}
		id = n
	}
	if id == 0 {
		return 0, ErrRefused
	}
	return id, nil
}
func mountPath(s string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		if len(s)-i < 4 {
			return "", false
		}
		escaped := s[i+1 : i+4]
		var c byte
		switch escaped {
		case "040":
			c = ' '
		case "011":
			c = '\t'
		case "012":
			c = '\n'
		case "134":
			c = '\\'
		default:
			return "", false
		}
		out.WriteByte(c)
		i += 3
	}
	return out.String(), true
}
