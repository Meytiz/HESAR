package system

import (
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
