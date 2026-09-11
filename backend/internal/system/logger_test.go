package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A partial settings submit (the panel sends log_path only from the loaded
// config, and API clients send even less) must never move the log file into
// the working directory or disable rotation — both used to happen because an
// empty value was applied verbatim.
func TestUpdateConfigTreatsEmptyValuesAsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hesar.log")
	if err := InitLogger(path, 8); err != nil {
		t.Fatalf("InitLogger: %v", err)
	}
	t.Cleanup(func() {
		GlobalLogger.Close()
		GlobalLogger = nil
	})

	if err := GlobalLogger.UpdateConfig("", 0); err != nil {
		t.Fatalf("UpdateConfig(\"\", 0): %v", err)
	}
	if GlobalLogger.filePath != path {
		t.Errorf("empty path must not move the log file (now %q, want %q)", GlobalLogger.filePath, path)
	}
	if GlobalLogger.maxSizeMB != 8 {
		t.Errorf("maxSizeMB = %d, want the stored 8 (0 must not disable rotation)", GlobalLogger.maxSizeMB)
	}
}

func TestUpdateConfigRollsBackWhenTheNewFileIsUnusable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hesar.log")
	if err := InitLogger(path, 8); err != nil {
		t.Fatalf("InitLogger: %v", err)
	}
	t.Cleanup(func() {
		GlobalLogger.Close()
		GlobalLogger = nil
	})

	// A path whose parent is a regular file can never be created — not even
	// by root, so the failure is deterministic.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := GlobalLogger.UpdateConfig(filepath.Join(blocker, "sub", "hesar.log"), 3); err == nil {
		t.Fatal("UpdateConfig must report a log file it cannot open")
	}

	if GlobalLogger.filePath != path || GlobalLogger.maxSizeMB != 8 {
		t.Errorf("state after failed update = (%q, %d), want the previous (%q, %d)",
			GlobalLogger.filePath, GlobalLogger.maxSizeMB, path, 8)
	}
	if GlobalLogger.file == nil {
		t.Fatal("the previous log handle must stay usable after a failed update")
	}

	LogInfo("after rollback %d", 1)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log back: %v", err)
	}
	if !strings.Contains(string(data), "after rollback 1") {
		t.Errorf("the logger stopped writing to %q; content was %q", path, string(data))
	}
}

// A daemon must not die because a log file is unwritable: that killed the
// documented `./hesar -config data/config.json` flow for unprivileged users.
func TestInitLoggerSurvivesAnUnusablePath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	if err := InitLogger(filepath.Join(blocker, "hesar.log"), 1); err == nil {
		t.Fatal("InitLogger must report that the file could not be opened")
	}
	t.Cleanup(func() {
		if GlobalLogger != nil {
			GlobalLogger.Close()
		}
		GlobalLogger = nil
	})
	if GlobalLogger == nil {
		t.Fatal("the logger must still be installed (in-memory buffer + live stream)")
	}
	if GlobalLogger.file != nil {
		t.Error("no file handle may be installed when the file is unusable")
	}

	LogInfo("buffered without a file")
	if len(GlobalLogger.recentLogs) != 1 {
		t.Errorf("recentLogs = %d, want 1 buffered entry", len(GlobalLogger.recentLogs))
	}
}

func TestSubscribeReceivesSnapshotAndLiveEntries(t *testing.T) {
	if err := InitLogger(filepath.Join(t.TempDir(), "hesar.log"), 10); err != nil {
		t.Fatalf("InitLogger: %v", err)
	}
	t.Cleanup(func() {
		GlobalLogger.Close()
		GlobalLogger = nil
	})

	LogInfo("history %d", 1)

	ch := GlobalLogger.Subscribe()
	defer GlobalLogger.Unsubscribe(ch)

	select {
	case msg := <-ch:
		if msg.Message != "history 1" {
			t.Fatalf("snapshot entry = %q, want %q", msg.Message, "history 1")
		}
	default:
		t.Fatal("Subscribe must deliver the recent-log snapshot immediately")
	}

	LogInfo("live %d", 2)
	select {
	case msg := <-ch:
		if msg.Message != "live 2" {
			t.Errorf("live entry = %q, want %q", msg.Message, "live 2")
		}
	default:
		t.Error("subscribers must receive new log lines without blocking")
	}
}
