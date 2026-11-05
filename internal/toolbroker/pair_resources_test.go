package toolbroker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPairResourceAdmission(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"valid", "smaller", "alias", "missing", "memory", "swap", "cpu", "pids", "unlimited", "negative", "malformed", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			makeRole := func(id string) map[string]any {
				return map[string]any{"Id": strings.Repeat(id, 64), "HostConfig": map[string]any{"Memory": PairMemoryBytes / 2, "MemorySwap": PairMemoryBytes / 2, "NanoCpus": PairNanoCPUs / 2, "PidsLimit": PairProcessLimit / 2}}
			}
			e, tool := makeRole("a"), makeRole("b")
			h := e["HostConfig"].(map[string]any)
			switch mode {
			case "smaller":
				h["Memory"] = int64(1)
				h["MemorySwap"] = int64(1)
			case "alias":
				tool["Id"] = e["Id"]
			case "missing":
				delete(h, "NanoCpus")
			case "memory":
				h["Memory"] = PairMemoryBytes
			case "swap":
				h["MemorySwap"] = PairMemoryBytes
			case "cpu":
				h["NanoCpus"] = PairNanoCPUs
			case "pids":
				h["PidsLimit"] = PairProcessLimit
			case "unlimited":
				h["PidsLimit"] = 0
			case "negative":
				h["Memory"] = -1
			}
			raw, _ := json.Marshal(e)
			other, _ := json.Marshal(tool)
			if mode == "malformed" {
				raw = []byte(`{`)
			}
			if mode == "duplicate" {
				raw = []byte(`{"Id":"` + strings.Repeat("a", 64) + `","Id":"` + strings.Repeat("b", 64) + `"}`)
			}
			err := VerifyPairResources(raw, other)
			if (err == nil) != (mode == "valid" || mode == "smaller") {
				t.Fatalf("unexpected resource admission: %v", err)
			}
		})
	}
}
