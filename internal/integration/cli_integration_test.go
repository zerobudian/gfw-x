package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// CLI E2E harness: builds the real gfwx binary once and runs commands as real
// subprocesses, asserting on exit codes and stdout/stderr.

var (
	cliOnce sync.Once
	cliBin  string
	cliErr  error
)

// buildCLI compiles cmd/gfwx into a temp binary shared by all CLI tests.
func buildCLI() (string, error) {
	cliOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gfwx-cli-*")
		if err != nil {
			cliErr = err
			return
		}
		cliBin = filepath.Join(dir, "gfwx")
		cmd := exec.Command("go", "build", "-o", cliBin, "gfw-x/cmd/gfwx")
		cmd.Dir = repoRoot()
		out, err := cmd.CombinedOutput()
		if err != nil {
			cliErr = err
			os.Stderr.Write(out)
			return
		}
	})
	return cliBin, cliErr
}

func repoRoot() string {
	wd, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return wd
		}
		wd = parent
	}
}

// syncBuf is a mutex-guarded bytes.Buffer safe for a process copy goroutine to
// write while the test reads it concurrently.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runCLI invokes the binary with args, stdin closed, and a timeout. It returns
// code, combined stdout, and a system error (timeout/kill) if applicable.
func runCLI(t *testing.T, timeout time.Duration, args ...string) (int, string, error) {
	t.Helper()
	bin, err := buildCLI()
	if err != nil {
		t.Fatalf("build gfwx: %v", err)
	}
	cmd := exec.Command(bin, args...)
	var buf syncBuf
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("wait: %v", err)
			}
		}
		return code, buf.String(), nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return -1, buf.String(), errTimeout
	}
}

var errTimeout = cmdErr{msg: "timeout"}

type cmdErr struct{ msg string }

func (e cmdErr) Error() string { return e.msg }

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestCLI_Version(t *testing.T) {
	code, out, err := runCLI(t, 10*time.Second, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if code != 0 {
		t.Fatalf("version exit=%d want 0, out=%q", code, out)
	}
	if !strings.Contains(out, "GFW X") && !strings.Contains(out, "gfw") {
		t.Fatalf("version output missing product name: %q", out)
	}
}

func TestCLI_Help(t *testing.T) {
	code, out, _ := runCLI(t, 10*time.Second, "help")
	if code != 0 {
		t.Fatalf("help exit=%d want 0", code)
	}
	// Usage must enumerate the commands.
	for _, c := range []string{"run", "validate", "bench", "export", "version"} {
		if !strings.Contains(out, c) {
			t.Fatalf("help missing command %q", c)
		}
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	code, out, _ := runCLI(t, 10*time.Second, "frobnicate")
	if code != 2 {
		t.Fatalf("unknown command exit=%d want 2, out=%q", code, out)
	}
	if !strings.Contains(out, "unknown command") {
		t.Fatalf("expected 'unknown command' on stderr, got %q", out)
	}
}

func TestCLI_NoArgsRuns(t *testing.T) {
	// Running with no args is treated as "run"; it should not crash instantly.
	code, out, err := runCLI(t, 3*time.Second, "--mode", "bogus")
	if err == errTimeout {
		t.Fatalf("unexpected: bad mode should exit immediately, not hang")
	}
	if err != nil {
		t.Fatalf("no-args/run: %v", err)
	}
	// bogus mode -> error on stderr, exit 2.
	if code != 2 {
		t.Fatalf("bogus mode exit=%d want 2, out=%q", code, out)
	}
}

func TestCLI_Validate(t *testing.T) {
	dir := t.TempDir()
	goodCfg := writeFile(t, dir, "good.yaml", validConfigYAML())
	badCfg := writeFile(t, dir, "bad.yaml", "server:\n  listen: \"0.0.0.0:\"\nlogging:\n  format: \"nope\"\n")
	goodRules := writeFile(t, dir, "rules.txt", "ALLOW example.com\nBLOCK *.ads.net\n")

	t.Run("valid_config_ok", func(t *testing.T) {
		code, out, _ := runCLI(t, 10*time.Second, "validate", "--config", goodCfg)
		if code != 0 {
			t.Fatalf("valid config exit=%d want 0, out=%q", code, out)
		}
		if !strings.Contains(out, "config OK") {
			t.Fatalf("missing 'config OK', out=%q", out)
		}
	})
	t.Run("invalid_config_rc1", func(t *testing.T) {
		code, out, _ := runCLI(t, 10*time.Second, "validate", "--config", badCfg)
		if code != 1 {
			t.Fatalf("invalid config exit=%d want 1, out=%q", code, out)
		}
		if !strings.Contains(out, "config invalid") {
			t.Fatalf("missing 'config invalid', out=%q", out)
		}
	})
	t.Run("missing_config_skips", func(t *testing.T) {
		code, out, _ := runCLI(t, 10*time.Second, "validate", "--config", filepath.Join(dir, "nope.yaml"))
		if code != 0 {
			t.Fatalf("missing config exit=%d want 0, out=%q", code, out)
		}
		if !strings.Contains(out, "no file") {
			t.Fatalf("missing 'no file (skipped)', out=%q", out)
		}
	})
	t.Run("valid_rules_ok", func(t *testing.T) {
		code, out, _ := runCLI(t, 10*time.Second, "validate", "--config", goodCfg, "--rules", goodRules)
		if code != 0 {
			t.Fatalf("valid rules exit=%d want 0, out=%q", code, out)
		}
		if !strings.Contains(out, "rules OK") {
			t.Fatalf("missing 'rules OK', out=%q", out)
		}
	})
	t.Run("bad_rules_rc1", func(t *testing.T) {
		badRules := writeFile(t, dir, "bad.txt", "NOTARULE gibberish\n")
		code, out, _ := runCLI(t, 10*time.Second, "validate", "--config", goodCfg, "--rules", badRules)
		if code != 1 {
			t.Fatalf("bad rules exit=%d want 1, out=%q", code, out)
		}
		if !strings.Contains(out, "rules invalid") {
			t.Fatalf("missing 'rules invalid', out=%q", out)
		}
	})
	t.Run("missing_rules_file_rc1", func(t *testing.T) {
		code, out, _ := runCLI(t, 10*time.Second, "validate", "--config", goodCfg, "--rules", filepath.Join(dir, "missing.txt"))
		if code != 1 {
			t.Fatalf("missing rules file exit=%d want 1, out=%q", code, out)
		}
	})
	t.Run("bad_flag_rc2", func(t *testing.T) {
		code, _, _ := runCLI(t, 10*time.Second, "validate", "--bogusflag")
		if code != 2 {
			t.Fatalf("bad flag exit=%d want 2", code)
		}
	})
}

func TestCLI_Bench(t *testing.T) {
	code, out, err := runCLI(t, 60*time.Second, "bench", "--flows", "500", "--workers", "2")
	if err != nil {
		t.Fatalf("bench: %v", err)
	}
	if code != 0 {
		t.Fatalf("bench exit=%d want 0, out=%q", code, out)
	}
	if !strings.Contains(out, "flows/sec") && !strings.Contains(out, "p99") && !strings.Contains(out, "req") {
		t.Fatalf("bench report missing metrics, out=%q", out)
	}
}

func TestCLI_Export(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "cfg.yaml", validConfigYAML())
	rules := writeFile(t, dir, "rules.txt", "ALLOW example.com\nBLOCK *.ads.net\n")
	outDir := filepath.Join(dir, "out")

	code, out, err := runCLI(t, 30*time.Second, "export", "--config", cfg, "--rules", rules, "--dir", outDir)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if code != 0 {
		t.Fatalf("export exit=%d want 0, out=%q", code, out)
	}
	if !strings.Contains(out, "exported") {
		t.Fatalf("missing 'exported', out=%q", out)
	}
	entries, _ := os.ReadDir(outDir)
	if len(entries) == 0 {
		t.Fatalf("export produced no files in %s", outDir)
	}
	_ = writeFile(t, dir, "bad_rules.txt", "BOGUS thing\n")
	code, _, _ = runCLI(t, 30*time.Second, "export", "--config", cfg, "--rules", filepath.Join(dir, "bad_rules.txt"), "--dir", filepath.Join(dir, "o2"))
	if code != 1 {
		t.Fatalf("export with bad rules exit=%d want 1", code)
	}
}

// TestCLI_RunGraceful validates the full `run` lifecycle: it starts a real
// gateway+API, then SIGINT triggers graceful shutdown and a clean exit 0.
func TestCLI_RunGraceful(t *testing.T) {
	bin, err := buildCLI()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	dir := t.TempDir()
	cfg := writeFile(t, dir, "cfg.yaml", validConfigYAML())

	cmd := exec.Command(bin, "run", "--config", cfg, "--no-gen")
	cmd.Dir = repoRoot()
	var buf syncBuf
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start run: %v", err)
	}

	// Wait for startup, then send SIGTERM for an orderly shutdown.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "started") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "started") {
		_ = cmd.Process.Kill()
		<-waitExit(cmd)
		t.Fatalf("gfwx run never reported startup, out=%q", buf.String())
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	exit := make(chan int, 1)
	go func() {
		_ = cmd.Wait()
		exit <- cmd.ProcessState.ExitCode()
	}()
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("run after SIGTERM exit=%d want 0, out=%q", code, buf.String())
		}
		if !strings.Contains(buf.String(), "shutting down") {
			t.Fatalf("missing 'shutting down' log, out=%q", buf.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("run did not exit after SIGTERM (timeout)")
	}
}

func waitExit(cmd *exec.Cmd) <-chan struct{} {
	ch := make(chan struct{})
	go func() { _ = cmd.Wait(); close(ch) }()
	return ch
}

// validConfigYAML returns a minimal but validating server+busy config.
func validConfigYAML() string {
	return `server:
  listen: "127.0.0.1:8443"
  lan_only: true
  auth:
    enabled: false
logging:
  format: "ring"
  queue_size: 1024
defaults:
  mode: "block"
`
}