#!/usr/bin/env python3
"""Linux network-namespace integration tests; requires root and iproute2."""
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "backend/internal/provision/layer3_helper.py"
BINARY = ROOT / "release/hesar-linux-amd64"


def run(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stdout}\n{result.stderr}")
    return result


ECHO = """import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',18082));s.listen()
def echo(c):
 try:
  while True:
   b=c.recv(65536)
   if not b: break
   c.sendall(b)
 finally: c.close()
while True:
 c,_=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
"""
CLIENT = """import hashlib,socket,threading
s=socket.create_connection(('127.0.0.1',18080),timeout=15);s.settimeout(30)
payload=bytes(range(256))*8192
errors=[]
def send():
 try: s.sendall(payload);s.shutdown(socket.SHUT_WR)
 except Exception as e: errors.append(e)
t=threading.Thread(target=send);t.start();data=bytearray()
while len(data)<len(payload):
 b=s.recv(65536)
 if not b: break
 data.extend(b)
t.join(30);assert not t.is_alive() and not errors and data==payload
s.close();print('2 MiB echo integrity PASS')
"""
REJECT = """import socket
s=socket.create_connection(('127.0.0.1',18080),timeout=5);s.settimeout(5);s.sendall(b'test')
try: assert s.recv(1)==b''
except ConnectionResetError: pass
finally: s.close()
"""


def main():
    token = secrets.token_hex(3)
    left, right = "hsl3t-a-" + token, "hsl3t-b-" + token
    vleft, vright = "hsl3v" + token + "a", "hsl3v" + token + "b"
    created = []
    processes = []
    with tempfile.TemporaryDirectory(prefix="hesar-l3-tests-") as temp:
        path = Path(temp)
        try:
            for name in (left, right):
                run("ip", "netns", "add", name)
                created.append(name)
                run("ip", "-n", name, "link", "set", "lo", "up")
            run("ip", "link", "add", vleft, "type", "veth", "peer", "name", vright)
            run("ip", "link", "set", vleft, "netns", left)
            run("ip", "link", "set", vright, "netns", right)
            for name, dev, address in ((left, vleft, "192.0.2.1/30"), (right, vright, "192.0.2.2/30")):
                run("ip", "-n", name, "addr", "add", address, "dev", dev)
                run("ip", "-n", name, "link", "set", dev, "up")
            for mode in ("gre", "ipip"):
                configs = []
                for index, name in enumerate((left, right)):
                    c = {"interface": "hsl3-link", "mode": mode,
                         "local_outer": f"192.0.2.{index+1}", "remote_outer": f"192.0.2.{2-index}",
                         "local_inner": f"10.77.0.{index+1}", "remote_inner": f"10.77.0.{2-index}",
                         "mtu": 1280, "table": 30077, "priority": 30077}
                    file = path / f"{mode}-{index}" / "link.json"
                    file.parent.mkdir()
                    file.write_text(json.dumps(c))
                    configs.append(file)
                    if mode == "gre" and index == 0:
                        # A pre-existing unrelated interface must survive up/down.
                        run("ip", "-n", name, "link", "add", "hsl3-link", "type", "dummy")
                        for action in ("up", "down"):
                            rejected = subprocess.run(["ip", "netns", "exec", name, sys.executable, str(HELPER), action, "--config", str(file)], capture_output=True, text=True, timeout=10)
                            assert rejected.returncode != 0 and "another configuration" in rejected.stderr
                            run("ip", "-n", name, "link", "show", "dev", "hsl3-link")
                        run("ip", "-n", name, "link", "del", "dev", "hsl3-link")
                    run("ip", "netns", "exec", name, sys.executable, HELPER, "up", "--config", file)
                    # Repeating setup must validate and preserve the existing link.
                    run("ip", "netns", "exec", name, sys.executable, HELPER, "up", "--config", file)
                run("ip", "netns", "exec", left, "ping", "-I", "10.77.0.1", "-c", "2", "-W", "2", "10.77.0.2")
                for protocol in ("tcp", "quic", "kcp"):
                    secret = secrets.token_hex(32)
                    logs = []
                    group = []
                    try:
                        for index, name in enumerate((right, left)):
                            t = {"id": "link", "name": "L3 test", "mode": "overseas" if index == 0 else "iran",
                                 "protocol": protocol, "status": "active", "encryption_key": secret,
                                 "remote_ip": "10.77.0.2", "remote_port": 18081, "local_ports": "18080",
                                 "target_host": "127.0.0.1", "target_port": 18082,
                                 "listen_address": "10.77.0.2" if index == 0 else "127.0.0.1",
                                 "underlay_interface": "hsl3-link", "quic_disable_pmtu": True, "dial_timeout_seconds": 8}
                            log = path / f"{mode}-{protocol}-{index}.log"
                            c = {"admin_username": "test-admin", "admin_password": secrets.token_urlsafe(24),
                                 "secret_key": secrets.token_hex(32), "listen_port": 18090 + index,
                                 "log_path": str(log), "log_max_size_mb": 10, "allowed_origins": [], "tunnels": [t]}
                            file = path / f"{mode}-{protocol}-{index}-app.json"
                            file.write_text(json.dumps(c))
                            logstream = open(path / f"{mode}-{protocol}-{index}-stdout.log", "w")
                            proc = subprocess.Popen(["ip", "netns", "exec", name, str(BINARY), "-config", str(file)], stdout=logstream, stderr=logstream)
                            processes.append((proc, logstream))
                            group.append((proc, logstream))
                            logs.append(log)
                        echo = subprocess.Popen(["ip", "netns", "exec", right, sys.executable, "-c", ECHO], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        processes.append((echo, None)); group.append((echo, None))
                        time.sleep(1)
                        for proc, _ in group:
                            assert proc.poll() is None, f"{mode}/{protocol} process stopped"
                        run("ip", "netns", "exec", left, sys.executable, "-c", CLIENT)
                        run("ip", "-n", left, "link", "set", "dev", "hsl3-link", "down")
                        offset = logs[1].stat().st_size
                        run("ip", "netns", "exec", left, sys.executable, "-c", REJECT)
                        time.sleep(0.1)
                        assert "unavailable or down" in logs[1].read_text()[offset:]
                        run("ip", "-n", left, "link", "set", "dev", "hsl3-link", "up")
                        # Linux drops device routes on link-down; restore the owned peer route.
                        run("ip", "-n", left, "route", "replace", "10.77.0.2/32", "dev", "hsl3-link", "src", "10.77.0.1", "table", "30077", "proto", "99")
                        run("ip", "-n", left, "route", "replace", "10.77.0.2/32", "dev", vleft, "src", "10.77.0.1", "table", "30077", "proto", "99")
                        offset = logs[1].stat().st_size
                        run("ip", "netns", "exec", left, sys.executable, "-c", REJECT)
                        time.sleep(0.1)
                        assert "another interface" in logs[1].read_text()[offset:]
                        run("ip", "-n", left, "route", "replace", "10.77.0.2/32", "dev", "hsl3-link", "src", "10.77.0.1", "table", "30077", "proto", "99")
                        print(f"PASS: {protocol.upper()} over {mode.upper()}, 2 MiB authenticated echo, link-down and wrong-route refusal", flush=True)
                    except Exception:
                        for index in range(2):
                            for suffix in (".log", "-stdout.log"):
                                failure_log = path / f"{mode}-{protocol}-{index}{suffix}"
                                if failure_log.exists():
                                    print(f"{failure_log.name}:\n{failure_log.read_text()[-8000:]}", flush=True)
                        raise
                    finally:
                        for proc, stream in group:
                            proc.terminate()
                            try: proc.wait(timeout=5)
                            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                            if stream: stream.close()
                for name, file in zip((left, right), configs):
                    if name == left:
                        run("ip", "-n", name, "link", "del", "dev", "hsl3-link")
                    run("ip", "netns", "exec", name, sys.executable, HELPER, "down", "--config", file)
                    run("ip", "netns", "exec", name, sys.executable, HELPER, "down", "--config", file)
        finally:
            for proc, stream in processes:
                if proc.poll() is None: proc.kill(); proc.wait()
                if stream and not stream.closed: stream.close()
            for name in reversed(created):
                run("ip", "netns", "del", name)


if __name__ == "__main__":
    main()
