package system

import (
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

func InitLogger(filePath string, maxSizeMB int) error {
	GlobalLogger = &Logger{
		filePath:    filePath,
		maxSizeMB:   maxSizeMB,
		subscribers: make(map[chan LogMessage]bool),
		recentLogs:  make([]LogMessage, 0, 200),
		maxRecent:   200,
	}
	return GlobalLogger.openFile()
}

func (l *Logger) openFile() error {
	if l.filePath == "" {
		l.filePath = "hesar.log"
	}
	// ✅ مجوز امن‌تر — فقط owner و group بخوانند
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
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

	oldPath := l.filePath + fmt.Sprintf(".%d.bak", time.Now().Unix())
	_ = os.Rename(l.filePath, oldPath)

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
	if len(backups) > 5 {
		sort.Strings(backups)
		for _, old := range backups[:len(backups)-5] {
			_ = os.Remove(old)
		}
	}

	_ = l.openFile()
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

// UpdateConfig — ✅ با بازگردانی در صورت خطا
func (l *Logger) UpdateConfig(filePath string, maxSizeMB int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	oldFile := l.file
	oldPath := l.filePath

	l.filePath = filePath
	l.maxSizeMB = maxSizeMB

	if err := l.openFile(); err != nil {
		// ✅ بازگردانی به حالت قبل
		l.filePath = oldPath
		l.file = oldFile
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
