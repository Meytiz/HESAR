//go:build linux

package provision

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func hostname(raw string) bool { return raw != "" && net.ParseIP(raw) == nil }

func needsDNS(e *coreEntry) bool {
	c := e.cfg
	cover := c.RealityTarget
	if cover == "" {
		cover = net.JoinHostPort(c.ServerName, "443")
	}
	host, _, _ := net.SplitHostPort(cover)
	return c.Carrier == "xray" && c.Mode == "overseas" && hostname(host) || c.Mode == "overseas" && hostname(c.TargetHost) || c.Carrier == "direct" && c.Mode == "iran" && hostname(c.RemoteIP)
}

// Permit only the configured IPv4 resolvers when this tunnel needs DNS.
func resolverRules(e *coreEntry) [][]string {
	if !needsDNS(e) {
		return nil
	}
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil || len(data) > 65536 {
		return nil
	}
	var rules [][]string
	count := 0
	tag := "hesar-" + entryName(e.cfg.ID)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(f[1])
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, protocol := range []string{"tcp", "udp"} {
			rules = append(rules, []string{"filter", "OUTPUT", "-d", ip.String(), "-p", protocol, "--dport", "53", "-m", "comment", "--comment", tag, "-j", "ACCEPT"}, []string{"filter", "INPUT", "-s", ip.String(), "-p", protocol, "--sport", "53", "-m", "comment", "--comment", tag, "-j", "ACCEPT"})
			if ip.IsLoopback() {
				rules = append(rules, []string{"filter", "INPUT", "-i", "lo", "-d", ip.String(), "-p", protocol, "--dport", "53", "-m", "comment", "--comment", tag, "-j", "ACCEPT"}, []string{"filter", "OUTPUT", "-o", "lo", "-s", ip.String(), "-p", protocol, "--sport", "53", "-m", "comment", "--comment", tag, "-j", "ACCEPT"})
			}
		}
		count++
		if count == 2 {
			break
		}
	}
	return rules
}

func (a *agent) resolveTargets(ctx context.Context, e *coreEntry, local string) error {
	resolve := func(host string) (string, error) {
		if net.ParseIP(host) != nil {
			return host, nil
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("cannot resolve configured IPv4 destination %s", host)
		}
		return ips[0].String(), nil
	}
	permit := func(host string, port int) {
		tag := "hesar-" + entryName(e.cfg.ID)
		e.rules = append(e.rules, []string{"filter", "OUTPUT", "-d", host, "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"}, []string{"filter", "INPUT", "-s", host, "-p", "tcp", "--sport", strconv.Itoa(port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"})
	}
	if e.cfg.Mode == "overseas" && hostname(e.cfg.TargetHost) {
		ip, err := resolve(e.cfg.TargetHost)
		if err != nil {
			return err
		}
		e.effective.TargetHost = ip
		permit(ip, e.cfg.TargetPort)
	}
	if e.cfg.Carrier == "direct" && e.cfg.Mode == "iran" && hostname(e.cfg.RemoteIP) {
		ip, err := resolve(e.cfg.RemoteIP)
		if err != nil {
			return err
		}
		e.effective.RemoteIP = ip
	}
	if e.cfg.Carrier == "xray" && e.cfg.Mode == "overseas" {
		target := e.cfg.RealityTarget
		if target == "" {
			target = net.JoinHostPort(e.cfg.ServerName, "443")
		}
		host, port, _ := net.SplitHostPort(target)
		ip, err := resolve(host)
		if err != nil {
			return err
		}
		number, _ := strconv.Atoi(port)
		permit(ip, number)
		e.cfg.RealityTarget = net.JoinHostPort(ip, port)
	}
	return a.installFirewall(ctx, e)
}
