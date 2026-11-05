package strictjson

import "testing"

func TestEncodingRefusesReplacement(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`"\ud800"`, `"\udfff"`, `"\ud800\u0041"`, `"\ud800x"`, `"\ud800\ud800"`, `"\uD800\uZZZZ"`, `"\u12"`, "\"\xff\"", `"\ud800\uDC00\udfff"`} {
		if ValidEncoding([]byte(raw)) {
			t.Fatalf("malformed encoding accepted: %q", raw)
		}
	}
}

func TestEncodingPreservesValidUnicodeAndLiteralEscapes(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`{"text":"hello"}`, `"é😀�"`, `"\uFFFD"`, `"\uD83D\uDE00"`, `"\ud800\udc00"`, `"\\ud800"`, `"\"escaped quote\""`, `"\u0041"`, `{"key":"\\","value":"\uD83D\uDE00"}`} {
		if !ValidEncoding([]byte(raw)) {
			t.Fatalf("valid encoding rejected: %q", raw)
		}
	}
}

func TestEncodingNoAllocation(t *testing.T) {
	input := []byte(`{"text":"\uD83D\uDE00"}`)
	if allocations := testing.AllocsPerRun(100, func() {
		if !ValidEncoding(input) {
			panic("invalid test fixture")
		}
	}); allocations != 0 {
		t.Fatalf("encoding validation allocated: %v", allocations)
	}
}
