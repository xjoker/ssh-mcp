package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveSerializesConcurrentProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(`
[settings]

[servers.existing]
host = "host.example"
user = "deploy"
auth = "agent"
`), 0600); err != nil {
		t.Fatal(err)
	}

	release, err := acquireSaveLock(path)
	if err != nil {
		t.Fatalf("acquireSaveLock: %v", err)
	}
	defer func() { _ = release() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type helper struct {
		command *exec.Cmd
		ready   string
		output  strings.Builder
	}
	helpers := make([]helper, 2)
	for index := range helpers {
		helpers[index].ready = filepath.Join(t.TempDir(), "ready")
		helpers[index].command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSaveLockHelperProcess$")
		helpers[index].command.Env = append(os.Environ(),
			"SSH_MCP_SAVE_LOCK_HELPER=1",
			"SSH_MCP_SAVE_LOCK_PATH="+path,
			fmt.Sprintf("SSH_MCP_SAVE_LOCK_DESCRIPTION=writer-%d", index),
			"SSH_MCP_SAVE_LOCK_READY="+helpers[index].ready,
		)
		helpers[index].command.Stdout = &helpers[index].output
		helpers[index].command.Stderr = &helpers[index].output
		if err := helpers[index].command.Start(); err != nil {
			t.Fatalf("start helper %d: %v", index, err)
		}
	}

	for index := range helpers {
		waitForFile(t, ctx, helpers[index].ready)
	}
	if err := release(); err != nil {
		t.Fatalf("release initial lock: %v", err)
	}
	release = func() error { return nil }

	successes := 0
	conflicts := 0
	for index := range helpers {
		err := helpers[index].command.Wait()
		output := helpers[index].output.String()
		if err == nil {
			successes++
		} else if strings.Contains(output, "changed on disk") {
			conflicts++
		} else {
			t.Fatalf("helper %d failed: %v\n%s", index, err, output)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent saves: successes=%d conflicts=%d, want one of each", successes, conflicts)
	}
}

func TestSaveLockHelperProcess(t *testing.T) {
	if os.Getenv("SSH_MCP_SAVE_LOCK_HELPER") != "1" {
		return
	}
	path := os.Getenv("SSH_MCP_SAVE_LOCK_PATH")
	cfg, err := Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	server := cfg.Servers["existing"]
	server.Description = os.Getenv("SSH_MCP_SAVE_LOCK_DESCRIPTION")
	if err := UpsertServer(cfg, "existing", server); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.WriteFile(os.Getenv("SSH_MCP_SAVE_LOCK_READY"), []byte("ready"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := Save(path, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func waitForFile(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for helper readiness: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
