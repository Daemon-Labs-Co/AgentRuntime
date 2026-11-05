package workerport

import (
	"bytes"
	"testing"
)

func TestLegacyVerificationLauncherCannotRun(t *testing.T) {
	t.Parallel()
	var out, log bytes.Buffer
	if workerVerifyConnection(workerAuthRequest{}, &out, &log) != 1 || out.Len() != 0 {
		t.Fatal("legacy unjournalled launch allowed")
	}
}
