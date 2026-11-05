package toolbroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func syntheticReadResult(t *testing.T, content string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	raw, err := json.Marshal(helperResult{Operation: "read", Bytes: len(content), SHA256: hex.EncodeToString(digest[:]), Encoding: "base64", Data: base64.StdEncoding.EncodeToString([]byte(content))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHelperResultRefusesMalformedAndMismatchedEvidence(t *testing.T) {
	t.Parallel()
	valid := string(syntheticReadResult(t, "fixture"))
	var wrongDigest helperResult
	json.Unmarshal([]byte(valid), &wrongDigest)
	wrongDigest.SHA256 = strings.Repeat("0", 64)
	wrongDigestRaw, _ := json.Marshal(wrongDigest)
	for _, raw := range []string{
		"", "ok", `null`, valid + ` {}`,
		string(wrongDigestRaw),
		string(syntheticReadResult(t, strings.Repeat("x", 8193))),
		strings.Replace(valid, `"operation":"read"`, `"operation":"write"`, 1),
		strings.Replace(valid, `"bytes":7`, `"bytes":6`, 1),
		strings.Replace(valid, `"bytes":7`, `"bytes":null`, 1),
		strings.Replace(valid, `"bytes":7`, `"bytes":-1`, 1),
		strings.Replace(valid, `"bytes":7`, `"bytes":1.5`, 1),
		strings.Replace(valid, `"bytes":7`, `"bytes":7,"bytes":7`, 1),
		strings.Replace(valid, `"bytes":7`, `"Bytes":7`, 1),
		strings.Replace(valid, `"bytes":7`, `"bytes":7,"\u0062ytes":7`, 1),
		strings.Replace(valid, `"bytes":7`, `"extra":7,"bytes":7`, 1),
		strings.Replace(valid, `"encoding":"base64"`, `"encoding":"text"`, 1),
		strings.Replace(valid, `"data":"Zml4dHVyZQ=="`, `"data":"ZmFrZQ=="`, 1),
		strings.Replace(valid, `"data":"Zml4dHVyZQ=="`, `"data":"\ud800"`, 1),
		strings.Replace(valid, `"data":"Zml4dHVyZQ=="`, `"data":"Zml4dHVyZR=="`, 1),
		strings.Replace(valid, `"data":"Zml4dHVyZQ=="`, `"data":"Zml4\n dHVyZQ=="`, 1),
		strings.Repeat(" ", MaxOutputBytes+1),
	} {
		if validHelperResult([]byte(raw), Action{Operation: "read"}) {
			t.Fatal("invalid helper result accepted")
		}
	}
	if !validHelperResult([]byte(valid), Action{Operation: "read"}) || !validHelperResult(syntheticReadResult(t, ""), Action{Operation: "read"}) {
		t.Fatal("valid read refused")
	}
}

func TestUnsupportedDeclaredToolRefusedBeforeDocker(t *testing.T) {
	t.Parallel()
	_, r := liveFixture(t)
	a, _, err := New(r.Scope, []string{"command", "patch"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewToolContainerPlan(a, "sha256:"+strings.Repeat("c", 64), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runner := mockDocker(func(context.Context, []string, []byte, io.Writer) error {
		t.Error("unsupported helper operation reached daemon")
		return nil
	})
	e := containerExecutor(t, p, runner, "/home/synthetic/docker")
	ctx, cancel := context.WithDeadline(context.Background(), a.scope.Deadline)
	defer cancel()
	for _, action := range []Action{{Operation: "command", Command: []string{"synthetic"}}, {Operation: "patch", Path: "file", Content: "synthetic"}} {
		if e.Execute(ctx, a.scope, action, io.Discard) != ErrRejected {
			t.Fatal("unsupported declared operation accepted")
		}
	}
}

func TestWriteResultBindsOriginalContent(t *testing.T) {
	t.Parallel()
	content := "synthetic"
	digest := sha256.Sum256([]byte(content))
	result := helperResult{Operation: "write", Bytes: len(content), SHA256: hex.EncodeToString(digest[:])}
	raw, _ := json.Marshal(result)
	if !validHelperResult(raw, Action{Operation: "write", Content: content}) {
		t.Fatal("matching write refused")
	}
	if validHelperResult(raw, Action{Operation: "write", Content: "different"}) {
		t.Fatal("different write content accepted")
	}
	raw = bytes.Replace(raw, []byte(`"bytes":9`), []byte(`"data":"","bytes":9`), 1)
	if validHelperResult(raw, Action{Operation: "write", Content: content}) {
		t.Fatal("write accepted unexpected content field")
	}
}

func TestInvalidHelperResultFencesWithoutPublishing(t *testing.T) {
	t.Parallel()
	p, _, raw, vol, root, scope, action := executorFixture(t)
	cleanup := 0
	runner := runtimeMock(t, raw, vol, func(_ context.Context, _ []string, _ []byte, out io.Writer) error {
		_, err := io.WriteString(out, `{"operation":"read","bytes":0,"sha256":"fake"}`)
		return err
	}, func(args []string, _ io.Writer) error {
		if args[0] == "ps" {
			cleanup++
		}
		return nil
	})
	e := containerExecutor(t, p, runner, root)
	ctx, cancel := context.WithDeadline(context.Background(), scope.Deadline)
	defer cancel()
	var out bytes.Buffer
	if e.Execute(ctx, scope, action, &out) != ErrExecution || out.Len() != 0 || cleanup != 1 {
		t.Fatal("invalid result published or cleanup skipped")
	}
	if _, err := p.RunArgs(time.Now()); err != ErrRejected {
		t.Fatal("invalid result did not fence job")
	}
}
