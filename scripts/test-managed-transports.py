#!/usr/bin/env python3
"""Exercise panel provisioning, peer export and teardown on isolated Linux links."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
BINARY = Path(os.environ.get("HESAR_TEST_BINARY", ROOT / "release/hesar-linux-amd64"))
AGENT = Path(os.environ.get("HESAR_TEST_AGENT", ROOT / "release/hesar-agent-linux-amd64"))
CORES = Path(os.environ.get("HESAR_TEST_CORES", ROOT / "release/vendor/amd64"))
spec = importlib.util.spec_from_file_location("layer3_tests", ROOT / "scripts/test-linux-layer3.py")
l3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(l3)
run = l3.run

HTTP_CLIENT = """import json,sys,urllib.request,urllib.error
request=json.loads(sys.argv[1]);headers={'Content-Type':'application/json'}
if request['token']: headers['Authorization']='Bearer '+request['token']
body=json.dumps(request['data']).encode() if request['data'] is not None else None
try:
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18090'+request['path'],data=body,headers=headers,method=request['method']),timeout=50) as response: print(response.read().decode())
except urllib.error.HTTPError as e: raise SystemExit(str(e.code)+': '+e.read().decode())
"""

DNS_SERVER = """import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.1',53))
while True:
 data,peer=s.recvfrom(4096)
 try:
  end=12
  while data[end]: end+=data[end]+1
  question=data[12:end+5]
  answer=struct.pack('!HHHLH',0xc00c,1,1,1,4)+socket.inet_aton('127.0.0.1')
  header=data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)
  s.sendto(header+question+answer,peer)
  print('DNS answer sent',flush=True)
 except (IndexError,struct.error): pass
"""


def main():
    if os.geteuid() != 0:
        raise SystemExit("Integration tests require root and Linux network namespaces")
    suffix = secrets.token_hex(3)
    names = ["hsma-" + suffix, "hsmb-" + suffix]
    devs = ["hsva" + suffix, "hsvb" + suffix]
    processes, created = [], []
    resolver_path=Path('/etc/netns')/names[1]
    resolver_created=False
    with tempfile.TemporaryDirectory(prefix="hesar-panel-tests-") as temp:
        path = Path(temp)
        path.chmod(0o755)  # Packaged cores run as nobody, not root.
        core_path = path / "cores"
        core_path.mkdir(mode=0o755)
        for name in ("paqet", "xray", "hysteria"):
            shutil.copyfile(CORES / name, core_path / name)
            (core_path / name).chmod(0o755)

        def launch(index, command, tag, env=None):
            stream = (path / (tag + ".log")).open("w")
            process = subprocess.Popen(["ip", "netns", "exec", names[index], *map(str, command)], stdout=stream, stderr=stream, env=env)
            processes.append((process, stream))
            return process

        def api(index, endpoint, data=None, token="", method="POST"):
            request = {"path": endpoint, "data": data, "token": token, "method": method}
            result = run("ip", "netns", "exec", names[index], sys.executable, "-c", HTTP_CLIENT, json.dumps(request))
            return json.loads(result.stdout)

        try:
            for name in names:
                run("ip", "netns", "add", name); created.append(name)
                run("ip", "-n", name, "link", "set", "lo", "up")
            run("ip", "link", "add", devs[0], "type", "veth", "peer", "name", devs[1])
            for index, name in enumerate(names):
                run("ip", "link", "set", devs[index], "netns", name)
                run("ip", "-n", name, "addr", "add", f"192.0.2.{index+1}/30", "dev", devs[index])
                run("ip", "-n", name, "link", "set", devs[index], "up")
                # A locked-down host keeps loopback management reachable;
                # physical tunnel traffic needs the agent-owned rules.
                run("ip","netns","exec",name,"iptables","-A","INPUT","-i","lo","-j","ACCEPT")
                run("ip","netns","exec",name,"iptables","-A","OUTPUT","-o","lo","-j","ACCEPT")
                for chain in ("INPUT","OUTPUT"):run("ip","netns","exec",name,"iptables","-P",chain,"DROP")
                if index==1:
                    resolver_path.mkdir(parents=True)
                    resolver_created=True
                    (resolver_path/'resolv.conf').write_text('nameserver 192.0.2.1\noptions timeout:2 attempts:2\n')
                socket = path / f"agent-{index}/control.sock"
                launch(index, [AGENT, "-socket", socket, "-state", path / f"state-{index}", "-cores", core_path, "-user", "nobody"], f"agent-{index}")
                cfg = {"admin_username": "qa", "admin_password": secrets.token_hex(24), "secret_key": secrets.token_hex(32), "listen_port": 18090,
                       "log_path": str(path / f"app-{index}.log"), "log_max_size_mb": 10, "tunnels": []}
                file = path / f"app-{index}.json"; file.write_text(json.dumps(cfg))
                env = os.environ.copy(); env["HESAR_AGENT_SOCKET"] = str(socket)
                launch(index, [BINARY, "-config", file], f"app-stdout-{index}", env)
            launch(1, [sys.executable, "-c", l3.ECHO], "echo")
            # DNS is a separate fixture. The outside agent must install its own
            # resolver allowances to reach it through default DROP.
            run('ip','netns','exec',names[0],'iptables','-A','INPUT','-s','192.0.2.2','-p','udp','--dport','53','-j','ACCEPT')
            run('ip','netns','exec',names[0],'iptables','-A','OUTPUT','-d','192.0.2.2','-p','udp','--sport','53','-j','ACCEPT')
            launch(0,[sys.executable,'-c',DNS_SERVER],'dns')
            time.sleep(1)
            tokens = [api(i, "/api/auth/login", {"username": "qa", "password": json.loads((path / f"app-{i}.json").read_text())["admin_password"]})["token"] for i in range(2)]
            for i in range(2):
                assert api(i, "/api/network/runtime", token=tokens[i], method="GET")["available"]
            cases = [("paqet","tcp")]
            cases.extend((carrier, protocol) for carrier in ("gre", "ipip") for protocol in ("tcp", "quic", "kcp"))
            cases.extend((carrier, "tcp") for carrier in ("hysteria", "xray"))
            cases.extend(("", protocol) for protocol in ("wss", "wss-shaped", "auto"))
            selection=os.environ.get("HESAR_TEST_CASES")
            if selection:
                wanted=set(selection.split(","))
                cases=[(c,p) for c,p in cases if f"{c or 'native'}/{p}" in wanted]
                if len(cases)!=len(wanted):raise ValueError("Unknown integration test selection")
            for carrier, protocol in cases:
                keys = api(1, "/api/network/keys", {"server_name": "localhost"}, tokens[1])
                if carrier == "xray":
                    (path / "cover.pem").write_text(keys["tls_cert_pem"])
                    (path / "cover-key.pem").write_text(keys["tls_key_pem"])
                    cover = launch(1, ["openssl", "s_server", "-accept", "18444", "-cert", path / "cover.pem", "-key", path / "cover-key.pem", "-tls1_3", "-www"], "cover")
                    time.sleep(0.2)
                tunnel = {"name": f"{carrier or 'native'}/{protocol}", "mode": "overseas", "protocol": protocol, "encryption_key": secrets.token_hex(32),
                          "status": "inactive", "remote_port": 18081, "local_ports": "18080", "target_host": "127.0.0.1", "target_port": 18082,
                          "remote_ip": "192.0.2.1", "carrier": carrier, "carrier_peer_ip": "192.0.2.1", "carrier_local_ip": "192.0.2.2",
                          "carrier_local_inner": "10.77.0.2", "carrier_remote_inner": "10.77.0.1", "carrier_mtu": 1280,
                          "carrier_port": 19999, "reality_target": "127.0.0.1:18444", "dial_timeout_seconds": 20, **keys}
                if protocol=='wss-shaped':tunnel['target_host']='echo.hesar.test'
                overseas = api(1, "/api/tunnels", tunnel, tokens[1])
                api(1, f"/api/tunnels/{overseas['id']}/start", {}, tokens[1])
                peer = api(1, "/api/network/peer-config", {"id": overseas["id"]}, tokens[1])["tunnel"]
                assert not peer.get("tls_key_pem") and not peer.get("reality_private_key")
                iran = api(0, "/api/tunnels", peer, tokens[0])
                api(0, f"/api/tunnels/{iran['id']}/start", {}, tokens[0])
                run("ip", "netns", "exec", names[0], sys.executable, "-c", l3.CLIENT)
                # Editing list output must preserve masked secrets and restart safely.
                masked = api(0, "/api/tunnels", token=tokens[0], method="GET")[0]
                masked["name"] += " edited"
                api(0, "/api/tunnels", masked, tokens[0])
                run("ip", "netns", "exec", names[0], sys.executable, "-c", l3.CLIENT)
                for index, stored in ((0, iran), (1, overseas)):
                    api(index, f"/api/tunnels/{stored['id']}/stop", {}, tokens[index])
                    api(index, f"/api/tunnels/{stored['id']}", token=tokens[index], method="DELETE")
                    runtime = api(index, "/api/network/runtime", token=tokens[index], method="GET")
                    assert not runtime.get("runtimes")
                    assert not list((path / f"state-{index}").glob("t-*"))
                    links = json.loads(run("ip", "-n", names[index], "-j", "link", "show").stdout)
                    assert not any(link["ifname"].startswith("hsl3-") for link in links)
                    rules = run("ip", "netns", "exec", names[index], "iptables-save").stdout
                    assert "hesar-t-" not in rules
                    assert ":INPUT DROP" in rules and ":OUTPUT DROP" in rules
                if carrier == "xray": cover.terminate(); cover.wait(timeout=5)
                if protocol=='wss-shaped':assert 'DNS answer sent' in (path/'dns.log').read_text()
                print(f"PASS: panel-only {carrier or 'native'}/{protocol}, peer export, masked active edit, 2 MiB integrity and complete teardown", flush=True)
        except Exception:
            # Generated private credentials stay in ephemeral test files; logs only.
            for file in path.glob("*.log"):
                print(file.name + "\n" + file.read_text()[-6000:], flush=True)
            raise
        finally:
            # Stop apps before agents so native listeners close before carriers.
            for process, stream in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=8)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                stream.close()
            for name in reversed(created): run("ip", "netns", "del", name)
            if resolver_created and resolver_path.is_dir():shutil.rmtree(resolver_path)


if __name__ == "__main__":
    main()
