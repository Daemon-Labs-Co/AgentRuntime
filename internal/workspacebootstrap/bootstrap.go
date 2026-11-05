// Package workspacebootstrap initializes approved source inside the isolated,
// credential-free tool container. It must never run against a host workspace.
package workspacebootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxBundleBytes int64 = 256 * 1024 * 1024
const MaxTreeBytes = 2 * 1024 * 1024
const MaxFiles = 10000
const MaxCheckoutBytes int64 = 256 * 1024 * 1024

var ErrRefused = errors.New("workspace bootstrap refused; outcome may be partial, do not retry")

type Receipt struct {
	Version    int    `json:"version"`
	Job        string `json:"job"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Branch     string `json:"branch"`
}

func hexDigest(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func ValidReceipt(r Receipt, job, digest string) bool {
	return r.Version == 1 && hexDigest(job, 32) && hexDigest(digest, 64) && r.Job == job && r.Repository == digest && (hexDigest(r.Commit, 40) || hexDigest(r.Commit, 64)) && r.Branch == "feature/commonroom-"+job
}

// Git is a trusted adapter: production invokes only fixed /usr/bin/git with a
// fresh HOME, no inherited configuration, hooks or network. Tests mock it.
// Output must be bounded to MaxTreeBytes; error text must not include source.
// A source fork CAN supply a host runner, BUT invalidates isolation guarantees.
type Git interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// Run owns a fresh, empty tool volume. The original bounded bundle is streamed
// and hashed before Git is invoked. Any failure leaves a nonempty unresolved
// workspace; it never removes or resets prior content or retries uncertain work.
// Container/journal lifetime and shutdown remain the worker's responsibility.
func Run(ctx context.Context, in io.Reader, out io.Writer, workspace, job, digest string, git Git) error {
	if ctx == nil || ctx.Err() != nil || in == nil || out == nil || git == nil || !hexDigest(job, 32) || !hexDigest(digest, 64) {
		return ErrRefused
	}
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrRefused
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		return ErrRefused
	}
	bundle := filepath.Join(workspace, ".commonroom-bootstrap.bundle")
	f, err := os.OpenFile(bundle, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrRefused
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, hash), io.LimitReader(&contextReader{ctx, in}, MaxBundleBytes+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n == 0 || n > MaxBundleBytes || hex.EncodeToString(hash.Sum(nil)) != digest || ctx.Err() != nil {
		return ErrRefused
	}
	run := func(dir string, args ...string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrRefused
		}
		raw, err := git.Run(ctx, dir, args...)
		if err != nil || len(raw) > MaxTreeBytes || ctx.Err() != nil {
			return nil, ErrRefused
		}
		return raw, nil
	}
	// Both the backing clone and task worktree live in the private tool volume.
	// Neither operation attaches a worktree to the operator's source checkout.
	source := filepath.Join(workspace, ".commonroom-source")
	repo := filepath.Join(workspace, "repository")
	if _, err = run(workspace, "clone", "--no-checkout", "--no-hardlinks", "--template=", "--", bundle, source); err != nil {
		return ErrRefused
	}
	if _, err = run(source, "remote", "remove", "origin"); err != nil {
		return ErrRefused
	}
	raw, err := run(source, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return ErrRefused
	}
	commit := strings.TrimSpace(string(raw))
	receipt := Receipt{1, job, digest, commit, "feature/commonroom-" + job}
	if !ValidReceipt(receipt, job, digest) {
		return ErrRefused
	}
	tree, err := run(source, "ls-tree", "-r", "-l", "-z", commit)
	if err != nil || !validTree(tree) {
		return ErrRefused
	}
	// Highest-priority attributes disable repository-controlled checkout filters,
	// encoding conversion and newline expansion. Blob-size admission then bounds
	// checkout bytes and cannot trigger helper programs from source attributes.
	infoDir := filepath.Join(source, ".git", "info")
	if err = os.MkdirAll(infoDir, 0700); err != nil {
		return ErrRefused
	}
	if err = os.WriteFile(filepath.Join(infoDir, "attributes"), []byte("* -filter -text -crlf -ident -working-tree-encoding -eol\n"), 0600); err != nil {
		return ErrRefused
	}
	if _, err = run(source, "worktree", "add", "--no-checkout", "-b", receipt.Branch, repo, commit); err != nil {
		return ErrRefused
	}
	if _, err = run(repo, "reset", "--hard", commit, "--"); err != nil {
		return ErrRefused
	}
	raw, err = run(repo, "rev-parse", "--verify", "HEAD")
	if err != nil || strings.TrimSpace(string(raw)) != commit {
		return ErrRefused
	}
	// Verify writable source and Git metadata without replacing repository files.
	for _, dir := range []string{repo, filepath.Join(source, ".git")} {
		file, err := os.CreateTemp(dir, ".commonroom-check-")
		if err != nil {
			return ErrRefused
		}
		_, writeErr := file.WriteString("bootstrap write check\n")
		syncErr := file.Sync()
		closeErr := file.Close()
		removeErr := os.Remove(file.Name())
		if writeErr != nil || syncErr != nil || closeErr != nil || removeErr != nil {
			return ErrRefused
		}
	}
	if err = os.Remove(bundle); err != nil || ctx.Err() != nil {
		return ErrRefused
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return ErrRefused
	}
	encoded = append(encoded, '\n')
	nout, err := out.Write(encoded)
	if err != nil || nout != len(encoded) || ctx.Err() != nil {
		return ErrRefused
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	in  io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	return r.in.Read(p)
}

func validTree(raw []byte) bool {
	if len(raw) > MaxTreeBytes {
		return false
	}
	if len(raw) == 0 {
		return true
	}
	if raw[len(raw)-1] != 0 {
		return false
	}
	records := strings.Split(string(raw[:len(raw)-1]), "\x00")
	if len(records) > MaxFiles {
		return false
	}
	var total int64
	seen := map[string]bool{}
	for _, record := range records {
		metadata, name, ok := strings.Cut(record, "\t")
		if !ok || name == "" || name == "." || len(name) > 4096 || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\r\n") || seen[name] {
			return false
		}
		seen[name] = true
		for _, segment := range strings.Split(name, "/") {
			if strings.EqualFold(segment, ".git") {
				return false
			}
		}
		fields := strings.Fields(metadata)
		if len(fields) != 4 || (fields[0] != "100644" && fields[0] != "100755") || fields[1] != "blob" || !(hexDigest(fields[2], 40) || hexDigest(fields[2], 64)) {
			return false
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > MaxCheckoutBytes-total {
			return false
		}
		total += size
	}
	return true
}
