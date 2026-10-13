//go:build linux

package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
)

// Explicit ACCEPT rules precede existing deny rules, restricted to the chosen
// endpoint/port. No default policy, existing chain or unrelated rule is changed.
func firewallRules(e *coreEntry, local string, socks int) [][]string {
	c := e.cfg
	tag := "hesar-" + entryName(c.ID)
	rules := resolverRules(e)
	add := func(chain string, args ...string) {
		r := append([]string{"filter", chain}, args...)
		r = append(r, "-m", "comment", "--comment", tag, "-j", "ACCEPT")
		rules = append(rules, r)
	}
	pair := func(local, peer, protocol string, port int, server bool, iface string) {
		in := []string{"-d", local, "-p", protocol}
		out := []string{"-s", local, "-p", protocol}
		if peer != "" {
			in = append(in, "-s", peer)
			out = append(out, "-d", peer)
		}
		if iface != "" {
			in = append(in, "-i", iface)
			out = append(out, "-o", iface)
		}
		if port > 0 {
			inputFlag, outputFlag := "--sport", "--dport"
			if server {
				inputFlag, outputFlag = "--dport", "--sport"
			}
			in = append(in, inputFlag, strconv.Itoa(port))
			out = append(out, outputFlag, strconv.Itoa(port))
		}
		add("INPUT", in...)
		add("OUTPUT", out...)
	}
	server := c.Mode == "overseas"
	if e.l3 {
		outerProtocol := "47"
		if c.Carrier == "ipip" {
			outerProtocol = "4"
		}
		pair(local, c.CarrierPeerIP, outerProtocol, 0, server, "")
		protocol := "udp"
		if c.Protocol == "tcp" {
			protocol = "tcp"
		}
		pair(c.CarrierLocalInner, c.CarrierRemoteInner, protocol, c.RemotePort, server, e.effective.UnderlayInterface)
	} else {
		protocols := []string{"tcp"}
		port := c.CarrierPort
		if c.Carrier == "hysteria" {
			protocols = []string{"udp"}
		}
		if c.Carrier == "direct" {
			port = c.RemotePort
			if c.Protocol == "quic" || c.Protocol == "kcp" {
				protocols = []string{"udp"}
			} else if c.Protocol == "auto" {
				protocols = []string{"tcp", "udp"}
			}
		}
		for _, protocol := range protocols {
			pair(local, c.CarrierPeerIP, protocol, port, server, "")
		}
		if c.Carrier != "direct" {
			loPort := socks
			if server {
				loPort = c.RemotePort
			}
			pair("127.0.0.1", "127.0.0.1", "tcp", loPort, true, "lo")
			pair("127.0.0.1", "127.0.0.1", "tcp", loPort, false, "lo")
		}
	}
	if server {
		host := c.TargetHost
		if host == "" {
			host = "127.0.0.1"
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			if ip.IsLoopback() {
				pair("127.0.0.1", host, "tcp", c.TargetPort, true, "lo")
				pair("127.0.0.1", host, "tcp", c.TargetPort, false, "lo")
			} else {
				pair(local, host, "tcp", c.TargetPort, false, "")
			}
		}
	}
	return rules
}

func (a *agent) installFirewall(ctx context.Context, e *coreEntry) error {
	data, err := json.Marshal(e.rules)
	if err != nil {
		return err
	}
	if err := a.write(e.dir, "firewall.json", data, false); err != nil {
		return err
	}
	for _, rule := range e.rules {
		exists, err := firewallRuleExists(ctx, rule)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		action := "-A"
		if rule[0] == "filter" {
			action = "-I"
		}
		if _, err := command(ctx, "iptables", firewallArgs(rule, action)...); err != nil {
			return err
		}
	}
	return nil
}

func firewallArgs(rule []string, action string) []string {
	return append([]string{"-w", "5", "-t", rule[0], action}, rule[1:]...)
}

func firewallRuleExists(ctx context.Context, rule []string) (bool, error) {
	err := exec.CommandContext(ctx, "iptables", firewallArgs(rule, "-C")...).Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("cannot inspect owned firewall rule: %w", err)
}

func neighborRules(e *coreEntry, local, device, next string) [][]string {
	tag := "hesar-" + entryName(e.cfg.ID)
	return [][]string{
		{"filter", "OUTPUT", "-o", device, "-s", local, "-d", next, "-p", "icmp", "--icmp-type", "echo-request", "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
		{"filter", "INPUT", "-i", device, "-s", next, "-d", local, "-p", "icmp", "--icmp-type", "echo-reply", "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
	}
}
