package toolbroker

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWireEncodingRefusedBeforeReplacement(t *testing.T) {
	t.Parallel()
	_, request, _ := fixture(t)
	request.Operation = "write"
	request.Content = "fixture"
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{`"\ud800"`, `"\udfff"`, `"\ud800\u0041"`, "\"\xff\""} {
		input := strings.Replace(string(raw), `"fixture"`, encoding, 1)
		if _, err := Decode(strings.NewReader(input)); err != ErrRejected {
			t.Fatal("wire content was silently replaced")
		}
	}
	for _, encoding := range []string{`"\ud83d\ude00"`, `"�"`, `"\\ud800"`} {
		input := strings.Replace(string(raw), `"fixture"`, encoding, 1)
		if _, err := Decode(strings.NewReader(input)); err != nil {
			t.Fatal("valid/literal Unicode refused")
		}
	}
}

func TestTypedEncodingRefusedBeforeMarshal(t *testing.T) {
	t.Parallel()
	for _, action := range []Action{
		{Operation: "read", Path: "bad\xff"},
		{Operation: "write", Path: "file", Content: "bad\xff"},
		{Operation: "command", Command: []string{"tool", "bad\xff"}},
	} {
		if validAction(action) {
			t.Fatal("typed invalid UTF-8 accepted")
		}
	}
	if !validAction(Action{Operation: "write", Path: "é", Content: "😀�"}) {
		t.Fatal("valid typed Unicode refused")
	}
	_, request, _ := fixture(t)
	request.Path = "bad\xff"
	raw, _ := json.Marshal(request)
	// Demonstrate why typed validation is separate: JSON itself would replace it.
	var changed Request
	if json.Unmarshal(raw, &changed) != nil || changed.Path == request.Path || !utf8.ValidString(changed.Path) {
		t.Fatal("test no longer exercises JSON replacement")
	}
	if validRequest(request) {
		t.Fatal("typed request accepted after lossy marshal")
	}
}
