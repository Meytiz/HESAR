#!/usr/bin/env python3
"""Manage an isolated HESAR GRE/IPIP link. 'plan' is read-only and portable."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys

PROTOCOL = "99"


def validate(config):
    fields = {"interface", "mode", "local_outer", "remote_outer", "local_inner", "remote_inner", "mtu", "table", "priority"}
    if not isinstance(config, dict) or set(config) != fields:
        raise ValueError(f"Required fields (no extras): {', '.join(sorted(fields))}")
    if any(not isinstance(config[field], str) for field in fields - {"mtu", "table", "priority"}):
        raise ValueError("Interface, mode and addresses must be strings")
    if not re.fullmatch(r"hsl3-[A-Za-z0-9_-]{1,10}", config["interface"]):
        raise ValueError("interface must be hsl3- followed by 1-10 ASCII characters")
    if config["mode"] not in ("gre", "ipip"):
        raise ValueError("mode must be gre or ipip")
    private = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    for field in ("local_outer", "remote_outer", "local_inner", "remote_inner"):
        address = ipaddress.IPv4Address(config[field])
        if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local or int(address) == 0xffffffff:
            raise ValueError(f"{field} must be unicast IPv4")
        if field.endswith("inner") and not any(address in network for network in private):
            raise ValueError("inner endpoints must be RFC1918 addresses")
        config[field] = str(address)
    if config["local_outer"] == config["remote_outer"] or config["local_inner"] == config["remote_inner"]:
        raise ValueError("Local and remote endpoints must differ")
    if set(config[f"{role}_outer"] for role in ("local", "remote")) & set(config[f"{role}_inner"] for role in ("local", "remote")):
        raise ValueError("Inner and outer endpoints must differ")
    for field, low, high in (("mtu", 576, 1480), ("table", 10000, 32000), ("priority", 10000, 32000)):
        if type(config[field]) is not int or not low <= config[field] <= high:
            raise ValueError(f"{field} must be an integer in {low}..{high}")
    return config


def alias(config):
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:20]
    return f"hesar-l3:{digest}"


def command(*args, allow_missing=False):
    flags = ["-N"] if "-j" in args else []
    result = subprocess.run(["ip", *flags, *map(str, args)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        if allow_missing and ("does not exist" in result.stderr or "Cannot find device" in result.stderr):
            return []
        raise RuntimeError(f"ip {' '.join(map(str, args))}: {result.stderr.strip()}")
    return json.loads(result.stdout) if "-j" in args else result.stdout


def routes(c):
    return command("-j", "-4", "route", "show", "table", c["table"], allow_missing=True)


def rules(c):
    return [r for r in command("-j", "-4", "rule", "show") if r.get("priority") == c["priority"]]


def rule_matches(rule, c):
    return (str(rule.get("table")) == str(c["table"]) and
            rule.get("src", "").removesuffix("/32") == c["local_inner"] and
            rule.get("dst", "").removesuffix("/32") == c["remote_inner"] and
            str(rule.get("protocol")) == PROTOCOL)


def link(c):
    return next((l for l in command("-j", "link", "show") if l["ifname"] == c["interface"]), None)


def owned(c, entry):
    if entry is None or entry.get("ifalias") != alias(c):
        raise RuntimeError("Interface is missing or belongs to another configuration; refusing mutation")


def operations(c, device=None):
    table, name = c["table"], c["interface"]
    create = ["tunnel", "add", name, "mode", c["mode"], "local", c["local_outer"], "remote", c["remote_outer"], "ttl", "64"]
    if device:
        create.extend(["dev", device])
    return [
        create,
        ["link", "set", "dev", name, "alias", alias(c)],
        ["link", "set", "dev", name, "mtu", c["mtu"]],
        ["addr", "add", c["local_inner"] + "/32", "peer", c["remote_inner"] + "/32", "dev", name, "noprefixroute"],
        ["-4", "route", "add", "unreachable", "default", "table", table, "metric", "42760", "proto", PROTOCOL],
        ["link", "set", "dev", name, "up"],
        ["-4", "route", "add", c["remote_inner"] + "/32", "dev", name, "src", c["local_inner"], "table", table, "proto", PROTOCOL],
        ["-4", "rule", "add", "priority", c["priority"], "from", c["local_inner"] + "/32", "to", c["remote_inner"] + "/32", "lookup", table, "protocol", PROTOCOL],
    ]


def validate_owned_state(c, allow_missing_peer=False):
    current_rules = rules(c)
    if len(current_rules) != 1 or not rule_matches(current_rules[0], c):
        raise RuntimeError("Policy rule does not match this configuration")
    current_routes = routes(c)
    allowed_counts = (1, 2) if allow_missing_peer else (2,)
    if len(current_routes) not in allowed_counts or any(str(r.get("protocol")) != PROTOCOL for r in current_routes):
        raise RuntimeError("Routing table contains foreign or missing routes")
    peer = next((r for r in current_routes if r.get("dst", "").removesuffix("/32") == c["remote_inner"]), None)
    deny = next((r for r in current_routes if r.get("type") in ("unreachable", 7, "7") and r.get("dst") in ("default", "0.0.0.0/0")), None)
    if deny is None or (peer is None and not (allow_missing_peer and len(current_routes) == 1)) or (peer is not None and (peer.get("dev") != c["interface"] or peer.get("prefsrc") != c["local_inner"])):
        raise RuntimeError(f"Missing peer route or unreachable fallback: {current_routes}")


def up(c, marker):
    current = link(c)
    if current:
        owned(c, current)
        validate_owned_state(c)
        addresses = command("-j", "-4", "addr", "show", "dev", c["interface"])[0]["addr_info"]
        if "UP" not in current["flags"] or current.get("mtu") != c["mtu"] or not any(a["local"] == c["local_inner"] for a in addresses):
            raise RuntimeError("Existing link differs from the expected state; inspect it before recreating")
        print("Link already configured")
        marker.write_text(alias(c), encoding="ascii")
        marker.chmod(0o600)
        return
    if rules(c) or routes(c):
        raise RuntimeError("Routing table or rule priority is already in use; choose another pair")
    local_addresses = command("-j", "-4", "addr", "show")
    if not any(a.get("local") == c["local_outer"] for entry in local_addresses for a in entry.get("addr_info", [])):
        raise RuntimeError("local_outer is not assigned to this server; use its real local IPv4")
    if any(a.get("local") in (c["local_inner"],c["remote_inner"]) for entry in local_addresses for a in entry.get("addr_info", [])):
        raise RuntimeError("Private inner endpoints overlap an existing host address")
    route = command("-j", "-4", "route", "get", c["remote_outer"], "from", c["local_outer"])[0]
    device = route.get("dev")
    if not device or device == c["interface"]:
        raise RuntimeError("Invalid or recursive outer route")
    outer = command("-j", "link", "show", "dev", device)[0]
    overhead = 24 if c["mode"] == "gre" else 20
    if c["mtu"] > outer["mtu"] - overhead:
        raise RuntimeError(f"MTU exceeds outer interface minus {overhead}-byte overhead")
    # Mark only after proving the namespace/table is free, before mutation.
    # This permits recovery if the kernel link vanishes during partial teardown.
    marker.write_text(alias(c), encoding="ascii")
    marker.chmod(0o600)
    completed = []
    try:
        for args in operations(c, device):
            command(*args)
            completed.append(args)
    except Exception as error:
        rollback_errors = []
        for args in reversed(completed):
            if args[:3] in (["-4", "rule", "add"], ["-4", "route", "add"]):
                inverse = args.copy()
                inverse[2] = "del"
                try:
                    command(*inverse)
                except Exception as rollback:
                    rollback_errors.append(str(rollback))
        if completed:
            try:
                command("link", "del", "dev", c["interface"])
            except Exception as rollback:
                rollback_errors.append(str(rollback))
        raise RuntimeError(f"Setup failed: {error}; rollback errors: {rollback_errors}") from error
    print("L3 link configured; bidirectional data testing is still required")


def down(c, marker):
    current = link(c)
    if current is None:
        if rules(c) or routes(c):
            if not marker.is_file() or marker.read_text(encoding="ascii") != alias(c):
                raise RuntimeError("Link is absent and routing ownership cannot be proven")
        else:
            print("Link is already absent")
            return
    else:
        owned(c, current)
    current_rules, current_routes = rules(c), routes(c)
    if len(current_rules)>1 or any(not rule_matches(r,c) for r in current_rules):
        raise RuntimeError("Policy rule contains foreign state")
    for r in current_routes:
        peer = (r.get("dst", "").removesuffix("/32") == c["remote_inner"] and r.get("dev") == c["interface"] and r.get("prefsrc") == c["local_inner"])
        deny = (r.get("type") in ("unreachable",7,"7") and r.get("dst") in ("default","0.0.0.0/0") and r.get("metric") == 42760)
        if str(r.get("protocol")) != PROTOCOL or not (peer or deny):
            raise RuntimeError("Routing table contains foreign state")
    # Remove the source address/link first; new sockets can no longer bind it.
    if current is not None:
        command("link", "del", "dev", c["interface"])
    if current_rules:
        command("-4", "rule", "del", "priority", c["priority"], "from", c["local_inner"] + "/32",
                "to", c["remote_inner"] + "/32", "lookup", c["table"], "protocol", PROTOCOL)
    if any(r.get("dst") in ("default","0.0.0.0/0") for r in current_routes):
        command("-4", "route", "del", "unreachable", "default", "table", c["table"], "metric", "42760", "proto", PROTOCOL)
    print("Owned L3 link and policy removed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "up", "down", "status"))
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = validate(json.loads(args.config.read_text(encoding="utf-8")))
    marker=args.config.parent / "link-owned"
    if args.action == "plan":
        for command_args in operations(config):
            print(shlex.join(["ip", *map(str, command_args)]))
        return
    if platform.system() != "Linux" or shutil.which("ip") is None:
        raise RuntimeError("Linux and iproute2 are required; plan works on any OS")
    if args.action in ("up", "down") and os.geteuid() != 0:
        raise RuntimeError("Run up/down as root (CAP_NET_ADMIN); the HESAR daemon needs no added capability")
    if args.action == "up":
        up(config,marker)
    elif args.action == "down":
        down(config,marker)
    else:
        print(json.dumps({"link": link(config), "routes": routes(config), "rules": rules(config)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
