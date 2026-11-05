package workerport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// limitedAgentOutput bounds captured stdout/stderr without disclosing secrets.
type limitedAgentOutput struct{ bytes.Buffer }

func (b *limitedAgentOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4*1024*1024 {
		return 0, errors.New("Agent output exceeded limit")
	}
	return b.Buffer.Write(p)
}

// isolationAvailable rejects unsupported hosts/configuration. There is no flag
// or direct-launch fallback. A fork CAN bypass this, BUT exposes host credentials,
// files and network access and invalidates the containment contract.
func isolationAvailable(endpoint string) error {
	if strings.HasPrefix(endpoint, "ssh://") {
		_, _, err := remoteWorkerEndpoint(endpoint, os.Getenv("COMMONROOM_REMOTE_WORKER_ALIAS"), os.Getenv("COMMONROOM_REMOTE_WORKER"))
		return err
	}
	if endpoint != "codex" && endpoint != "claude" {
		return errors.New("Remote agent execution is blocked until an isolated remote worker is configured")
	}
	if runtime.GOOS != "linux" {
		return errors.New("Isolated agent execution currently requires a Linux worker with rootless Docker")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("Rootless Docker is required; direct agent execution is disabled")
	}
	if !validAgentImage(os.Getenv("COMMONROOM_AGENT_IMAGE")) {
		return errors.New("Set COMMONROOM_AGENT_IMAGE to a trusted image pinned by sha256 digest")
	}
	return nil
}

// verifiedLocalDockerContext rejects a daemon that cannot enforce required
// limits and any non-local or environment-overridden Docker context. Shared by
// every caller that is about to shell out to "docker" for isolated execution
// (the single-container agent path here and the tool-container runner in
// tool_broker_runner.go) so this check is defined once, not duplicated.
func verifiedLocalDockerContext(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	info, err := exec.CommandContext(checkCtx, "docker", "info", "--format", "{{json .}}").Output()
	cancel()
	if err != nil || !dockerSecurityReady(info) {
		return errors.New("Docker must be reachable, rootless, seccomp-enabled and able to enforce CPU, memory/swap and process limits")
	}
	// Do not silently use remote Docker contexts: mounts and cleanup belong here.
	checkCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	host, err := exec.CommandContext(checkCtx, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").Output()
	cancel()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(host)), "unix://") {
		return errors.New("Only a local Unix-socket Docker context is supported")
	}
	if os.Getenv("DOCKER_HOST") != "" || os.Getenv("DOCKER_CONTEXT") != "" {
		return errors.New("Docker environment overrides are unsupported; select the local rootless context explicitly")
	}
	return nil
}

func validAgentImage(value string) bool {
	if strings.HasPrefix(value, "sha256:") && len(value) == 71 {
		_, err := hex.DecodeString(value[7:])
		return err == nil
	}
	parts := strings.Split(value, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) != 64 || strings.HasPrefix(value, "-") || strings.ContainsAny(value, " \t\n\r") {
		return false
	}
	_, err := hex.DecodeString(parts[1])
	return err == nil
}

// dockerSecurityReady fails closed when the daemon cannot enforce required limits.
func dockerSecurityReady(raw []byte) bool {
	var info struct {
		SecurityOptions                                []string
		MemoryLimit, SwapLimit, PidsLimit, CpuCfsQuota bool
	}
	if json.Unmarshal(raw, &info) != nil {
		return false
	}
	security := strings.Join(info.SecurityOptions, " ")
	return strings.Contains(security, "name=rootless") && strings.Contains(security, "name=seccomp") && info.MemoryLimit && info.SwapLimit && info.PidsLimit && info.CpuCfsQuota
}

func isolatedRunArgs(image, name, volume, socket, credential, provider string, args []string) []string {
	out := []string{"run", "-i", "--rm", "--pull=never", "--name", name, "--label", "commonroom.managed=true", "--init", "--network=none", "--read-only", "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=128", "--memory=1g", "--memory-swap=1g", "--cpus=1", "--ulimit", "nofile=1024:1024", "--log-driver=none", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777", "--mount", "type=volume,src=" + volume + "-work,dst=/workspace", "--mount", "type=volume,src=" + volume + ",dst=/home/agent", "--mount", "type=bind,src=" + socket + ",dst=/run/provider.sock,readonly", "--mount", "type=bind,src=" + credential + ",dst=/run/provider-auth.json,readonly", "--workdir", "/workspace", "--env", "HOME=/home/agent", "--env", "HTTP_PROXY=http://127.0.0.1:18080", "--env", "HTTPS_PROXY=http://127.0.0.1:18080", "--env", "NO_PROXY=", "--env", "NODE_USE_ENV_PROXY=1", "--entrypoint", "node", image, "/opt/commonroom/entrypoint.cjs", provider}
	return append(out, args...)
}

// Development changes only the private workspace and provider tool policy; the
// rootless container boundary remains mandatory. A source bypass CAN expose host
// authority, BUT invalidates containment and must never be an automatic fallback.
func localIsolatedDevelopmentCommand(ctx context.Context, endpoint, key, jobID, repository string, toolSeparation bool, args ...string) (*exec.Cmd, func(), error) {
	if err := requireCredentialSeparatedDevelopment(repository); err != nil {
		return nil, nil, err
	}
	bundle, err := workerDevelopmentBundle(key, repository, os.Getenv("COMMONROOM_WORKER_DEVELOPMENT"), os.Getenv("COMMONROOM_WORKER_DEVELOPMENT_REPOSITORIES"))
	if err != nil {
		return nil, nil, err
	}
	if developmentTurnArgs(endpoint, args) != (repository != "") || toolSeparation != toolSeparationTurnArgs(endpoint, args) || toolSeparation && repository == "" {
		return nil, nil, errors.New("Provider policy does not match the workspace")
	}

	if strings.TrimSpace(key) == "" || len(key) > 1024 {
		return nil, nil, errors.New("Isolated execution requires a bounded membership identity")
	}
	if err := isolationAvailable(endpoint); err != nil {
		return nil, nil, err
	}
	if err := verifiedLocalDockerContext(ctx); err != nil {
		return nil, nil, err
	}
	authRoot := os.Getenv("COMMONROOM_AGENT_AUTH_DIR")
	if authRoot == "" {
		authRoot = ".data/agent-auth"
	}
	filename := "auth.json"
	if endpoint == "claude" {
		filename = ".credentials.json"
	}
	connection, err := executionConnectionID(key)
	if err != nil {
		return nil, nil, err
	}
	credentialPath := filepath.Join(authRoot, connectionAuthKey(connection), endpoint, filename)
	if !workerCredentialReady(filepath.Dir(credentialPath)) {
		return nil, nil, errors.New("Connection credential recovery required; fence prior execution and complete provider sign-in")
	}
	raw, err := readPrivateBounded(credentialPath, 65536)
	if err != nil || len(raw) > 65536 || !json.Valid(raw) {
		return nil, nil, errors.New("Provider credential file must contain bounded valid JSON")
	}
	dir, err := os.MkdirTemp("", "commonroom-isolated-")
	if err != nil {
		return nil, nil, err
	}
	cleanupDir := func() { os.RemoveAll(dir) }
	if repository != "" {
		bundle, err = stageDevelopmentBundle(bundle, repository, dir)
		if err != nil {
			cleanupDir()
			return nil, nil, err
		}
	}
	credential := filepath.Join(dir, "auth.json")
	if err = stageContainerCredential(credential, raw); err != nil {
		cleanupDir()
		return nil, nil, err
	}
	gateway, err := newProviderGateway(ctx, filepath.Join(dir, "provider.sock"), endpoint)
	if err != nil {
		cleanupDir()
		return nil, nil, err
	}
	digest := sha256.Sum256([]byte(key + repository))
	volume := "commonroom-session-" + hex.EncodeToString(digest[:16])
	name := "commonroom-turn-" + id()
	if jobID != "" {
		if !validWorkerJobID(jobID) {
			gateway.Close()
			cleanupDir()
			return nil, nil, errors.New("Invalid worker job identity")
		}
		name = "commonroom-turn-" + jobID
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			gateway.Close()
			cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			// Kill the complete container, including descendants, even if the CLI client
			// was cancelled before reporting a result. Failures remain operator-visible.
			if err := exec.CommandContext(cleanupCtx, "docker", "rm", "--force", name).Run(); err != nil {
				fmt.Fprintln(os.Stderr, "Isolated container cleanup could not be confirmed:", name)
			}
			cleanupDir()
		})
	}
	runArgs := isolatedRunArgs(os.Getenv("COMMONROOM_AGENT_IMAGE"), name, volume, gateway.socket, credential, endpoint, args)
	if repository != "" {
		runArgs = developmentRunArgs(runArgs, bundle, repository, volume)
	}
	cmd := exec.CommandContext(ctx, "docker", runArgs...)
	// Only Docker selection and minimum platform variables, never provider keys.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	cmd.WaitDelay = 2 * time.Second
	return cmd, cleanup, nil
}

// providerGateway permits HTTPS tunnels to exact provider hosts only. DNS results
// are checked and the selected public IP is dialed directly to resist rebinding.
// TLS stays end-to-end; an allowed provider can still receive supplied context.
type providerGateway struct {
	socket      string
	server      *http.Server
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]bool
	closed      bool
	slots       chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	lookupIP    func(context.Context, string, string) ([]net.IP, error)
}

// Claude subscription and Console OAuth both exchange tokens at platform.claude.com.
// Permit exact authentication hosts only; never broaden this to a wildcard or host fallback.
func providerHostAllowed(provider, host string) bool {
	if provider == "codex" {
		return host == "api.openai.com" || host == "chatgpt.com" || host == "auth.openai.com"
	}
	return provider == "claude" && (host == "api.anthropic.com" || host == "console.anthropic.com" || host == "claude.ai" || host == "claude.com" || host == "platform.claude.com")
}

func publicProviderIP(ip net.IP) bool {
	if ip.To4() == nil {
		// Only native currently allocated global-unicast space is supported.
		// Translation/transition routes can conceal a private IPv4 destination;
		// IsGlobalUnicast alone does not establish ordinary public reachability.
		_, native, _ := net.ParseCIDR("2000::/3")
		if !native.Contains(ip) {
			return false
		}
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3ffe::/16", "3fff::/20"} {
		_, reserved, _ := net.ParseCIDR(cidr)
		if reserved.Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !(ip.To4() != nil && ip[0] == 169 && ip[1] == 254)
}

func newProviderGateway(ctx context.Context, socket, provider string) (*providerGateway, error) {
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(socket, 0666); err != nil {
		l.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	bounded := &gatewayListener{Listener: l, slots: make(chan struct{}, maximumGatewayConnections)}
	g := &providerGateway{socket: socket, listener: bounded, connections: map[net.Conn]bool{}, slots: make(chan struct{}, 8), ctx: ctx, cancel: cancel, lookupIP: net.DefaultResolver.LookupIP}
	g.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.connect(w, r, provider) })}
	go g.server.Serve(bounded)
	return g, nil
}

func (g *providerGateway) Close() {
	// Cancel pre-tunnel resolution/dialing as well as established connections.
	// A source fork CAN omit this, BUT then shutdown leaves work in flight.
	if g.cancel != nil {
		g.cancel()
	}
	g.mu.Lock()
	g.closed = true
	for c := range g.connections {
		c.Close()
	}
	g.mu.Unlock()
	g.server.Close()
}

func (g *providerGateway) connect(w http.ResponseWriter, r *http.Request, provider string) {
	host, port, err := net.SplitHostPort(r.Host)
	if r.Method != "CONNECT" || err != nil || port != "443" || !providerHostAllowed(provider, host) {
		http.Error(w, "Destination denied", 403)
		return
	}
	if g.ctx.Err() != nil {
		http.Error(w, "Gateway stopped", http.StatusServiceUnavailable)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "Gateway busy", 429)
		return
	}
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	lookup := g.lookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIP
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		http.Error(w, "Provider unavailable", 502)
		return
	}
	for _, ip := range ips {
		if !publicProviderIP(ip) {
			http.Error(w, "Destination denied", 403)
			return
		}
	}
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
	if err != nil {
		http.Error(w, "Provider unavailable", 502)
		return
	}
	defer upstream.Close()
	client, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	g.mu.Lock()
	if g.closed || g.ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	g.connections[client] = true
	g.connections[upstream] = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.connections, client); delete(g.connections, upstream); g.mu.Unlock() }()
	deadline := time.Now().Add(3 * time.Minute)
	client.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffer.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() { io.Copy(upstream, io.LimitReader(buffer, 32*1024*1024)); upstream.Close(); close(done) }()
	io.Copy(client, io.LimitReader(upstream, 32*1024*1024))
	client.Close()
	<-done
}
