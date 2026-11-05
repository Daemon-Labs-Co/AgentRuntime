package workspacemount

import (
	"strings"
	"testing"
)

func TestMountObservationParser(t *testing.T) {
	t.Parallel()
	root := "1 0 0:1 / / ro - overlay overlay ro\n"
	workspace := "2 1 0:2 / /workspace ro,nosuid - ext4 /dev/synthetic rw\n"
	for _, tc := range []struct {
		name, raw string
		good      bool
	}{
		{"readonly bind on writable backing filesystem", root + workspace, true},
		{"writable", root + strings.Replace(workspace, "ro,nosuid", "rw,nosuid", 1), false},
		{"contradictory", root + strings.Replace(workspace, "ro,nosuid", "ro,rw", 1), false},
		{"missing", root, false}, {"duplicate", root + workspace + workspace, false},
		{"stacked", root + workspace + strings.Replace(workspace, "2 1", "3 1", 1), false},
		{"submount", root + workspace + "3 2 0:3 / /workspace/cache ro - tmpfs tmpfs ro\n", false},
		{"escaped submount", root + workspace + `3 2 0:3 / /workspace/a\040b ro - tmpfs tmpfs ro` + "\n", false},
		{"invalid escape", root + workspace + `3 2 0:3 / /other\057bad ro - tmpfs tmpfs ro` + "\n", false},
		{"malformed", root + workspace + "junk\n", false},
		{"oversize", strings.Repeat("x", MaxMountInfoBytes+1), false},
		{"negative id", root + strings.Replace(workspace, "2 1", "-2 1", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, e := mountID([]byte(tc.raw))
			if (e == nil) != tc.good || (tc.good && id != 2) {
				t.Fatalf("id=%d err=%v", id, e)
			}
		})
	}
}
func TestProofBinding(t *testing.T) {
	t.Parallel()
	challenge := strings.Repeat("a", 32)
	valid := Proof{1, challenge, 2, true, true}
	if !ValidProof(valid, challenge) {
		t.Fatal("healthy proof refused")
	}
	for _, change := range []func(*Proof){func(p *Proof) { p.Version = 0 }, func(p *Proof) { p.Challenge = strings.Repeat("b", 32) }, func(p *Proof) { p.MountID = 0 }, func(p *Proof) { p.ReadOnly = false }, func(p *Proof) { p.RootReadOnly = false }} {
		p := valid
		change(&p)
		if ValidProof(p, challenge) {
			t.Fatal("invalid proof accepted")
		}
	}
	for _, s := range []string{"", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("g", 32)} {
		if ValidChallenge(s) {
			t.Fatal("invalid challenge")
		}
	}
}

func TestFixedObjectMountParser(t *testing.T) {
	t.Parallel()
	root := "1 0 0:1 / / ro - overlay overlay ro\n"
	object := "2 1 0:2 / /objects ro,nosuid - ext4 /dev/synthetic rw\n"
	for _, tc := range []struct {
		name, raw string
		good      bool
	}{
		{"read only", root + object, true},
		{"writable", root + strings.Replace(object, "ro,nosuid", "rw", 1), false},
		{"missing", root, false},
		{"workspace is not objects", root + strings.Replace(object, "/objects", "/workspace", 1), false},
		{"submount", root + object + "3 2 0:3 / /objects/nested ro - tmpfs tmpfs ro\n", false},
		{"escaped submount", root + object + `3 2 0:3 / /objects/a\040b ro - tmpfs tmpfs ro` + "\n", false},
		{"stacked", root + object + strings.Replace(object, "2 1", "3 1", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := mountIDAt([]byte(tc.raw), "/objects")
			if (err == nil) != tc.good || tc.good && id != 2 {
				t.Fatal(id, err)
			}
		})
	}
	if _, err := mountIDAt([]byte(root+object), "/home"); err == nil {
		t.Fatal("arbitrary host mount accepted")
	}
}
