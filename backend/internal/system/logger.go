package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type LogMessage struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type Logger struct {
	mu          sync.Mutex
	filePath    string
	maxSizeMB   int
	file        *os.File
	subscribers map[chan LogMessage]bool
	recentLogs  []LogMessage
	maxRecent   int
}

var GlobalLogger *Logger

// defaultLogFilePath is used only when the daemon was started without any
// usable configured log path. It is intentionally a relative path: writing
// into the process' working directory is the least surprising fallback for a
// bare `./hesar` run, while packaged deployments always set an absolute
// log_path (the installer uses /var/log/hesar.log).
const defaultLogFilePath = "hesar.log"

// maxKeptBackups bounds how many rotated log files survive cleanup.
const maxKeptBackups = 5

// InitLogger installs the process-wide logger and returns the result of
// opening the log file.
//
// vNext fix: the daemon used to abort when /var/log/hesar.log could not be
// created. That made the documented "run directly" flow (`./hesar -config
// data/config.json` as an unprivileged user) fail permanently with
// "[FATAL] Failed to initialize logger", and it also let a purely cosmetic
// problem — where to persist a text file — take down every configured
// tunnel. The logger is therefore ALWAYS installed: if the file cannot be
// opened, l.file stays nil, log lines keep going into the in-memory ring
// buffer (so the panel's live WebSocket stream still works) and a warning is
// echoed to stderr, which systemd captures in the unit's journal.
func InitLogger(filePath string, maxSizeMB int) error {
	if filePath == "" {
		filePath = defaultLogFilePath
	}
	l := &Logger{
		filePath:    filePath,
		maxSizeMB:   maxSizeMB,
		subscribers: make(map[chan LogMessage]bool),
		recentLogs:  make([]LogMessage, 0, 200),
		maxRecent:   200,
	}
	err := l.openFile()
	GlobalLogger = l
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] file logging disabled (%v); continuing with in-memory log buffer only\n", err)
	}
	return err
}

func (l *Logger) openFile() error {
	if l.filePath == "" {
		return errors.New("log file path is empty")
	}
	// Create the parent directory: operators routinely point log_path at a
	// path that only exists once the first log line is written (e.g.
	// /var/log/hesar/hesar.log), and a missing directory used to be the
	// exact failure that killed startup.
	if dir := filepath.Dir(l.filePath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create log directory %s: %w", dir, err)
		}
	}
	// ✅ مجوز امن‌تر — فقط owner و group بخوانند
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", l.filePath, err)
	}
	l.file = f
	return nil
}

// rotateAndCleanup — ✅ چرخش فایل + پاک‌سازی فایل‌های قدیمی
func (l *Logger) rotateAndCleanup() {
	if l.file == nil {
		return
	}
	_ = l.file.Close()

	// Nanosecond precision: two rotations can legitimately land in the same
	// second under a burst of log lines, and a second-resolution suffix made
	// the second rename overwrite the first backup silently.
	oldPath := l.filePath + fmt.Sprintf(".%d.bak", time.Now().UnixNano())
	if err := os.Rename(l.filePath, oldPath); err != nil {
		// l.file still refers to the original inode, so appending continues
		// into the unrotated file — but say so loudly: a silent failure here
		// means the log grows past its configured cap forever.
		fmt.Fprintf(os.Stderr, "[WARN] log rotation: rename %s -> %s failed: %v\n", l.filePath, oldPath, err)
	}

	// ✅ حداکثر ۵ فایل backup نگه دار
	dir := filepath.Dir(l.filePath)
	base := filepath.Base(l.filePath)
	entries, _ := os.ReadDir(dir)

	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base) && strings.HasSuffix(e.Name(), ".bak") {
			backups = append(backups, filepath.Join(dir, e.Name()))
		}
	}
	if len(backups) > maxKeptBackups {
		sort.Strings(backups)
		for _, old := range backups[:len(backups)-maxKeptBackups] {
			_ = os.Remove(old)
		}
	}

	// If the fresh log file cannot be created, drop the (already closed)
	// handle instead of keeping it: writing to a closed *os.File never
	// succeeds, and pretending otherwise hides the fact that persistence is
	// gone. The ring buffer and the live WebSocket stream keep working, and
	// the next UpdateConfig/restart can point at a writable path again.
	if err := l.openFile(); err != nil {
		l.file = nil
		fmt.Fprintf(os.Stderr, "[WARN] log rotation: cannot reopen %v\n", err)
	}
}

func (l *Logger) checkRotation() {
	if l.file == nil || l.maxSizeMB <= 0 {
		return
	}
	info, err := l.file.Stat()
	if err != nil {
		return
	}
	if info.Size() >= int64(l.maxSizeMB)*1024*1024 {
		l.rotateAndCleanup()
	}
}

// UpdateConfig re-points the logger at a new file and/or rotation size, with
// a full rollback if the new file cannot be opened.
//
// "Empty" now means "unchanged" for both arguments, mirroring how the rest of
// the codebase treats optional fields. The previous behaviour was a
// configuration-corruption bug: the panel's settings form (and any partial
// API call) that omitted log_path sent "" here, which openFile() silently
// rewrote to "hesar.log" — so the daemon started logging into whatever the
// current working directory happened to be (under systemd: /etc/hesar, with
// ProtectSystem=strict) — and a 0 maxSizeMB disabled rotation permanently,
// letting the log file grow until the disk was full.
func (l *Logger) UpdateConfig(filePath string, maxSizeMB int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if filePath == "" {
		filePath = l.filePath
	}
	if maxSizeMB <= 0 {
		maxSizeMB = l.maxSizeMB
	}
	if filePath == l.filePath && maxSizeMB == l.maxSizeMB {
		return nil // nothing to do — never reopen the same file needlessly
	}

	oldFile, oldPath, oldMax := l.file, l.filePath, l.maxSizeMB

	l.filePath = filePath
	l.maxSizeMB = maxSizeMB
	l.file = nil
	if err := l.openFile(); err != nil {
		// ✅ بازگردانی کامل به حالت قبل (path, size AND file handle)
		l.filePath, l.maxSizeMB, l.file = oldPath, oldMax, oldFile
		return err
	}

	if oldFile != nil {
		_ = oldFile.Close()
	}
	return nil
}

// Subscribe registers a new live-log subscriber and delivers a snapshot of
// the recent backlog first.
//
// vNext fix: the old implementation delivered the snapshot from a detached
// goroutine. If the subscriber disconnected quickly, Unsubscribe could
// close(ch) while that goroutine was still sending → "send on closed
// channel" panic (a crash bug). The channel is now sized to always hold
// the full snapshot (maxRecent) plus live headroom, so the snapshot can be
// delivered INLINE under the lock without ever blocking: no goroutine, no
// post-close send, no race.
func (l *Logger) Subscribe() chan LogMessage {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := make(chan LogMessage, l.maxRecent+50)
	l.subscribers[ch] = true

	for _, msg := range l.recentLogs {
		// Guaranteed non-blocking: len(recentLogs) <= maxRecent < cap(ch).
		ch <- msg
	}

	return ch
}

func (l *Logger) Unsubscribe(ch chan LogMessage) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.subscribers[ch]; ok {
		delete(l.subscribers, ch)
		close(ch)
	}
}

func (l *Logger) log(level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	msgText := fmt.Sprintf(format, args...)
	logStr := fmt.Sprintf("[%s] [%s] %s\n", now.Format("2006-01-02 15:04:05"), level, msgText)

	// File
	if l.file != nil {
		_, _ = io.WriteString(l.file, logStr)
		l.checkRotation()
	}

	// Internal Buffer
	logMsg := LogMessage{
		Timestamp: now.Format("2006-01-02 15:04:05"),
		Level:     level,
		Message:   msgText,
	}

	if len(l.recentLogs) >= l.maxRecent {
		l.recentLogs = l.recentLogs[1:]
	}
	l.recentLogs = append(l.recentLogs, logMsg)

	// Subscribers — ✅ غیرمسدودکننده
	for ch := range l.subscribers {
		select {
		case ch <- logMsg:
		default:
			// بافر پر — رد کن
		}
	}
}

func LogInfo(format string, args ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.log("INFO", format, args...)
	} else {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}

func LogWarn(format string, args ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.log("WARN", format, args...)
	} else {
		fmt.Printf("[WARN] "+format+"\n", args...)
	}
}

func LogError(format string, args ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.log("ERROR", format, args...)
	} else {
		fmt.Printf("[ERROR] "+format+"\n", args...)
	}
}

// Close — ✅ بستن امن فایل لاگ
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}

	// بستن تمام subscriber‌ها
	for ch := range l.subscribers {
		close(ch)
	}
	l.subscribers = make(map[chan LogMessage]bool)
}
