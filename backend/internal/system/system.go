package system

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

type SystemInfo struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryTotal uint64  `json:"memory_total"`
	MemoryUsed  uint64  `json:"memory_used"`
	MemoryUsage float64 `json:"memory_usage"`
	LoadAvg1    float64 `json:"load_avg_1"`
	LoadAvg5    float64 `json:"load_avg_5"`
	LoadAvg15   float64 `json:"load_avg_15"`
	BBRActive   bool    `json:"bbr_active"`
}

var (
	cachedCPU     float64
	cpuCacheMu    sync.RWMutex
	cachedBBR     bool
	bbrCacheTime  time.Time
	bbrCacheMu    sync.Mutex
	collectorOnce sync.Once
)

func ensureCPUCollector() {
	collectorOnce.Do(func() {
		go func() {
			for {
				percents, err := cpu.Percent(5*time.Second, false)
				if err == nil && len(percents) > 0 {
					cpuCacheMu.Lock()
					cachedCPU = percents[0]
					cpuCacheMu.Unlock()
				}
			}
		}()
	})
}

func getCachedBBR() bool {
	bbrCacheMu.Lock()
	defer bbrCacheMu.Unlock()
	if time.Since(bbrCacheTime) < 30*time.Second {
		return cachedBBR
	}
	cachedBBR = checkBBRRaw()
	bbrCacheTime = time.Now()
	return cachedBBR
}

func checkBBRRaw() bool {
	cmd := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "bbr"
}

func GetSystemMetrics() SystemInfo {
	ensureCPUCollector()
	var info SystemInfo
	cpuCacheMu.RLock()
	info.CPUUsage = cachedCPU
	cpuCacheMu.RUnlock()
	vMem, err := mem.VirtualMemory()
	if err == nil {
		info.MemoryTotal = vMem.Total
		info.MemoryUsed = vMem.Used
		info.MemoryUsage = vMem.UsedPercent
	}
	avg, err := load.Avg()
	if err == nil {
		info.LoadAvg1 = avg.Load1
		info.LoadAvg5 = avg.Load5
		info.LoadAvg15 = avg.Load15
	}
	info.BBRActive = getCachedBBR()
	return info
}

func CheckBBR() bool {
	return getCachedBBR()
}

func EnableBBR() error {
	commands := [][]string{
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
	}
	var firstErr error
	for _, c := range commands {
		cmd := exec.Command(c[0], c[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			msg := fmt.Sprintf("failed to run %v: %s", c, strings.TrimSpace(string(out)))
			if firstErr == nil {
				firstErr = fmt.Errorf("%s", msg)
			}
		}
	}
	bbrCacheMu.Lock()
	bbrCacheTime = time.Time{}
	bbrCacheMu.Unlock()
	return firstErr
}

func OptimizeNetwork() error {
	sysctls := map[string]string{
		"fs.file-max":                  "1048576",
		"net.ipv4.tcp_tw_reuse":        "1",
		"net.ipv4.tcp_fin_timeout":     "15",
		"net.ipv4.ip_local_port_range": "1024 65535",
		"net.core.somaxconn":           "65535",
		"net.ipv4.tcp_max_syn_backlog": "65535",
		"net.core.netdev_max_backlog":  "65535",
		"net.ipv4.tcp_rmem":            "4096 87380 67108864",
		"net.ipv4.tcp_wmem":            "4096 65536 67108864",
	}
	var firstErr error
	successCount := 0
	for k, v := range sysctls {
		cmd := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", k, v))
		if out, err := cmd.CombinedOutput(); err != nil {
			LogWarn("Failed to optimize %s: %s", k, strings.TrimSpace(string(out)))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to optimize %s", k)
			}
		} else {
			successCount++
		}
	}
	LogInfo("Network optimization: %d/%d succeeded", successCount, len(sysctls))
	if successCount == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}