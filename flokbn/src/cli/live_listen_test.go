package cli

import (
	"bufio"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// A1: the listener binds [live] listen, loopback by default
// ============================================================================

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"":            true, // default
		"127.0.0.1":   true,
		"127.8.9.10":  true,
		"::1":         true,
		"localhost":   true,
		"0.0.0.0":     false,
		"::":          false,
		"192.168.1.5": false,
		"example.com": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}

// nonLoopbackIPv4 returns an IPv4 address of this machine that is not on the
// loopback interface, or "" when it has none.
func nonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
			return ipn.IP.String()
		}
	}
	return ""
}

// liveProcess is a running `flokbn live` subprocess with its stderr captured.
type liveProcess struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	logs strings.Builder
	done chan error
}

func (p *liveProcess) stderr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.String()
}

// startLive starts `flokbn live <args>` and waits until the ingest listener
// is serving.
func startLive(t *testing.T, args ...string) *liveProcess {
	t.Helper()
	p := &liveProcess{cmd: exec.Command(flokbnBin, append([]string{"live"}, args...)...), done: make(chan error, 1)}
	pipe, err := p.cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pipe)
		signalled := false
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.logs.WriteString(line + "\n")
			p.mu.Unlock()
			if !signalled && strings.Contains(line, "waiting for Filebeat to connect") {
				signalled = true
				close(ready)
			}
		}
		p.done <- p.cmd.Wait()
	}()
	t.Cleanup(func() { _ = p.cmd.Process.Kill() })
	select {
	case <-ready:
	case err := <-p.done:
		t.Fatalf("flokbn live exited before listening: %v\nstderr:\n%s", err, p.stderr())
	case <-time.After(20 * time.Second):
		t.Fatalf("flokbn live did not start listening within 20s\nstderr:\n%s", p.stderr())
	}
	return p
}

// stop sends one SIGINT and expects a clean exit.
func (p *liveProcess) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("signal: %v", err)
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Errorf("flokbn live exited with %v after one SIGINT, want a clean exit\nstderr:\n%s", err, p.stderr())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("flokbn live did not exit within 15s of SIGINT\nstderr:\n%s", p.stderr())
	}
}

func liveFlagArgs(t *testing.T, port string, extra ...string) []string {
	dir := t.TempDir()
	args := []string{
		"--port", port,
		"--jailFile", filepath.Join(dir, "jail.json"),
		"--banFile", filepath.Join(dir, "ban.txt"),
		"--clusterArgSet", "100,24,32,0.5",
	}
	return append(args, extra...)
}

func canDial(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TestLiveListen_DefaultIsLoopback: the Lumberjack port used to bind every
// interface (":port"). Without an explicit listen address it must now be
// reachable on loopback only.
func TestLiveListen_DefaultIsLoopback(t *testing.T) {
	port := freePort(t)
	p := startLive(t, liveFlagArgs(t, port)...)

	if want := "listen=127.0.0.1:" + port; !strings.Contains(p.stderr(), want) {
		t.Errorf("startup log lacks %q:\n%s", want, p.stderr())
	}
	if strings.Contains(p.stderr(), "reachable from other hosts") {
		t.Errorf("loopback bind must not warn about exposure:\n%s", p.stderr())
	}
	if !canDial(net.JoinHostPort("127.0.0.1", port)) {
		t.Errorf("listener not reachable on 127.0.0.1:%s", port)
	}
	if ext := nonLoopbackIPv4(); ext == "" {
		t.Log("no non-loopback IPv4 address on this machine; skipping the outside-reachability check")
	} else if canDial(net.JoinHostPort(ext, port)) {
		t.Errorf("listener reachable on %s:%s although no listen address was configured", ext, port)
	}
	p.stop(t)
}

// TestLiveListen_ExplicitWildcard: receiving from other hosts is an explicit
// opt-in, by flag or by config key, and is called out in the log.
func TestLiveListen_ExplicitWildcard(t *testing.T) {
	check := func(t *testing.T, port string, p *liveProcess) {
		t.Helper()
		if want := "listen=0.0.0.0:" + port; !strings.Contains(p.stderr(), want) {
			t.Errorf("startup log lacks %q:\n%s", want, p.stderr())
		}
		if !strings.Contains(p.stderr(), "reachable from other hosts") {
			t.Errorf("wildcard bind must warn that the port is exposed:\n%s", p.stderr())
		}
		if !canDial(net.JoinHostPort("127.0.0.1", port)) {
			t.Errorf("listener not reachable on 127.0.0.1:%s", port)
		}
		if ext := nonLoopbackIPv4(); ext != "" && !canDial(net.JoinHostPort(ext, port)) {
			t.Errorf("listener not reachable on %s:%s despite listen 0.0.0.0", ext, port)
		}
		p.stop(t)
	}

	t.Run("flag", func(t *testing.T) {
		port := freePort(t)
		check(t, port, startLive(t, liveFlagArgs(t, port, "--listen", "0.0.0.0")...))
	})

	t.Run("config", func(t *testing.T) {
		port := freePort(t)
		dir := t.TempDir()
		cfg := writeFile(t, dir, "live.toml", `
[global]
jailFile = "`+filepath.Join(dir, "jail.json")+`"
banFile = "`+filepath.Join(dir, "ban.txt")+`"

[live]
port = "`+port+`"
listen = "0.0.0.0"

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
sleepBetweenIterations = 1
clusterArgSets = [[100, 24, 32, 0.5]]
useForJail = [true]
`)
		check(t, port, startLive(t, "--config", cfg))
	})
}

// --listen is a flags-mode flag: like --port it cannot be combined with --config.
func TestLiveListen_FlagRejectedWithConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "live.toml", "[live]\nport = \"5045\"\n")
	_, err := runAppCaptured(t, []string{"flokbn", "live", "--config", cfg, "--listen", "0.0.0.0"})
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("live --config X --listen Y: err = %v, want an error naming --listen", err)
	}
}
