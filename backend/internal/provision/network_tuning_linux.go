//go:build linux

package provision

import (
	"context"
	"strings"
	"time"
)

// Only fixed, conservative settings are accepted; the caller cannot choose
// a sysctl key/value or request module loading/global firewall changes.
func (a *agent) optimize() Reply {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	reply := Reply{Available: true}
	for _, setting := range []string{"net.core.rmem_max=8388608", "net.core.wmem_max=8388608"} {
		if _, err := command(ctx, "sysctl", "-w", setting); err != nil {
			reply.Warnings = append(reply.Warnings, err.Error())
		}
	}
	available, err := command(ctx, "sysctl", "-n", "net.ipv4.tcp_available_congestion_control")
	if err == nil && strings.Contains(" "+strings.TrimSpace(string(available))+" ", " bbr ") {
		for _, setting := range []string{"net.core.default_qdisc=fq", "net.ipv4.tcp_congestion_control=bbr"} {
			if _, err := command(ctx, "sysctl", "-w", setting); err != nil {
				reply.Warnings = append(reply.Warnings, err.Error())
			}
		}
	} else {
		reply.Warnings = append(reply.Warnings, "BBR is not available in the current kernel; congestion control was retained")
	}
	current, _ := command(ctx, "sysctl", "-n", "net.ipv4.tcp_congestion_control")
	reply.BBRActive = strings.TrimSpace(string(current)) == "bbr"
	return reply
}
