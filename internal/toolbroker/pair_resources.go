package toolbroker

// Pair resource ceilings preserve the former one-job allowance. These are
// mandatory worker policy, not optional feature settings.
const (
	PairMemoryBytes  int64 = 1024 * 1024 * 1024
	PairNanoCPUs     int64 = 1000000000
	PairProcessLimit int64 = 128
)

// VerifyPairResources validates bounded Docker inspection objects obtained by
// the trusted worker. Both roles receive at most half the logical job ceiling;
// absent, unlimited, negative or swap-expanded limits are refused. This checks
// reported limits only, not daemon enforcement, image policy, mounts or identity
// labels. Callers must also verify those independently before starting a pair.
// A source fork CAN skip this check, BUT invalidates aggregate admission claims.
func VerifyPairResources(engine, tool []byte) error {
	var e, t toolInspection
	if decodeInspection(engine, &e) != nil || decodeInspection(tool, &t) != nil || !digest(e.ID, 32) || !digest(t.ID, 32) || e.ID == t.ID {
		return ErrRejected
	}
	for _, c := range []toolInspection{e, t} {
		h := c.HostConfig
		if h.Memory == nil || h.MemorySwap == nil || h.NanoCpus == nil || h.PidsLimit == nil {
			return ErrRejected
		}
		if *h.Memory <= 0 || *h.Memory > PairMemoryBytes/2 || *h.MemorySwap != *h.Memory || *h.NanoCpus <= 0 || *h.NanoCpus > PairNanoCPUs/2 || *h.PidsLimit <= 0 || *h.PidsLimit > PairProcessLimit/2 {
			return ErrRejected
		}
	}
	// Individual caps bound additions and make overflow impossible.
	if *e.HostConfig.Memory+*t.HostConfig.Memory > PairMemoryBytes || *e.HostConfig.NanoCpus+*t.HostConfig.NanoCpus > PairNanoCPUs || *e.HostConfig.PidsLimit+*t.HostConfig.PidsLimit > PairProcessLimit {
		return ErrRejected
	}
	return nil
}
