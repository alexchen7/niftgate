"""Run as root with: unshare --mount --net python3 tests/integration_destinations.py.

All interfaces, DNS fixtures, listeners and nftables changes stay in disposable
namespaces. This script refuses to run in the host network or mount namespace.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nft_forward.cli import main as cli
from nft_forward.config import load_settings
from nft_forward.destination_sync import sync_destinations


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=15).stdout.strip()


def main():
    for namespace in ("net", "mnt"):
        if os.readlink(f"/proc/self/ns/{namespace}") == os.readlink(f"/proc/1/ns/{namespace}"):
            raise SystemExit("Refusing to run outside isolated mount and network namespaces")
    run("mount", "--make-rprivate", "/")
    run("ip", "link", "set", "lo", "up")
    run("sysctl", "-w", "net.ipv4.ip_forward=1")
    children = []
    with tempfile.TemporaryDirectory(prefix="niftgate-integration-") as td:
        root = Path(td)
        hosts = root / "hosts"
        hosts.write_text("127.0.0.1 localhost\n10.252.0.2 forward.niftgate.test\n")
        run("mount", "--bind", str(hosts), "/etc/hosts")
        config = root / "config.json"
        config.write_text(json.dumps({"ddns_timeout": 1, "paths": {
            "state_db": str(root / "state.db"), "nft_conf": str(root / "forward.conf"),
            "audit_log": str(root / "audit.jsonl"),
        }}))
        settings = load_settings(config)

        def command(*args):
            assert cli(["--config", str(config), *args]) == 0, args

        def namespace(name, subnet):
            child = subprocess.Popen(["unshare", "--net", "sleep", "300"])
            children.append(child)
            for _ in range(100):
                if os.readlink(f"/proc/{child.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                    break
                time.sleep(0.01)
            peer = name + "p"
            run("ip", "link", "add", name, "type", "veth", "peer", "name", peer)
            run("ip", "addr", "add", subnet + ".1/24", "dev", name)
            run("ip", "link", "set", name, "up")
            run("ip", "link", "set", peer, "netns", str(child.pid))
            prefix = ["nsenter", "-t", str(child.pid), "-n"]
            run(*prefix, "ip", "link", "set", "lo", "up")
            run(*prefix, "ip", "addr", "add", subnet + ".2/24", "dev", peer)
            run(*prefix, "ip", "link", "set", peer, "up")
            run(*prefix, "ip", "route", "add", "default", "via", subnet + ".1")
            return prefix, peer

        try:
            client, _ = namespace("ngc", "10.251.0")
            server, server_if = namespace("ngs", "10.252.0")
            run(*server, "ip", "addr", "add", "10.252.0.3/24", "dev", server_if)
            server_code = '''
import socketserver,threading,time
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(1024)
            if not data: break
            self.request.sendall(self.server.marker+data)
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        sock.sendto(self.server.marker+data,self.client_address)
for ip,port,marker in [('10.252.0.2',58002,b'old:'),('10.252.0.3',58002,b'dns:'),('10.252.0.3',58004,b'port:')]:
    for cls,handler in [(socketserver.ThreadingTCPServer,TCP),(socketserver.ThreadingUDPServer,UDP)]:
        srv=cls((ip,port),handler); srv.marker=marker
        threading.Thread(target=srv.serve_forever,daemon=True).start()
print('ready',flush=True)
time.sleep(300)
'''
            service = subprocess.Popen([*server, sys.executable, "-u", "-c", server_code], stdout=subprocess.PIPE, text=True)
            children.append(service)
            assert service.stdout.readline().strip() == "ready"
            command("add-rule", "58001", "https://forward.niftgate.test/path?x=1", "58002", "--no-apply")
            command("add-rule", "58005", "10.252.0.2", "58002", "--no-apply")
            # Geo lookups are unnecessary for this isolated firewall fixture.
            from nft_forward.state import State
            state = State(settings.paths.state_db)
            state.add_allow("public", "10.251.0.2/32", "manual", 32)
            state.close()
            command("apply")

            def connect(port):
                code = '''
import socket,sys
s=socket.create_connection(('10.251.0.1',int(sys.argv[1])),3); s.settimeout(3)
print('ready',flush=True)
for line in sys.stdin:
    s.sendall(line.strip().encode()); print(s.recv(1024).decode(),flush=True)
'''
                proc = subprocess.Popen([*client, sys.executable, "-u", "-c", code, str(port)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                children.append(proc)
                assert proc.stdout.readline().strip() == "ready"
                return proc

            def exchange(proc, expected):
                proc.stdin.write("probe\n")
                proc.stdin.flush()
                assert proc.stdout.readline().strip() == expected + ":probe"

            old_connection, neighbor = connect(58001), connect(58005)
            exchange(old_connection, "old")
            exchange(neighbor, "old")
            before = run("nft", "-a", "list", "table", "ip", "nft_forward")
            mtime = settings.paths.nft_conf.stat().st_mtime_ns
            for _ in range(3):
                assert sync_destinations(settings) == 0
            assert settings.paths.nft_conf.stat().st_mtime_ns == mtime
            assert run("nft", "-a", "list", "table", "ip", "nft_forward") == before
            print("PASS: unchanged DNS leaves live nftables and config untouched")

            hosts.write_text("127.0.0.1 localhost\n10.252.0.3 forward.niftgate.test\n")
            assert sync_destinations(settings) == 1
            exchange(connect(58001), "dns")
            exchange(old_connection, "old")
            exchange(neighbor, "old")
            print("PASS: changed DNS routes new connections to new IP; existing TCP sessions survive")

            command("edit-rule", "58001", "--new-lport", "58003", "--dest-port", "58004")
            exchange(connect(58003), "port")
            exchange(old_connection, "old")
            exchange(neighbor, "old")
            rendered = run("nft", "list", "table", "ip", "nft_forward")
            assert "58001" not in rendered
            udp = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'probe',('10.251.0.1',58003)); print(s.recv(1024).decode())"
            assert run(*client, sys.executable, "-c", udp) == "port:probe"
            print("PASS: listening/destination port edits and TCP/UDP forwarding; old port removed")

            hosts.write_text("127.0.0.1 localhost\n")
            assert sync_destinations(settings) == 0
            exchange(connect(58003), "port")
            print("PASS: failed DNS keeps the last working destination")
            command("edit-rule", "58003", "--dest-ip", "10.252.0.2", "--dest-port", "58002")
            exchange(connect(58003), "old")
            command("delete-rule", "58003")
            assert sync_destinations(settings) == 0
            assert "58003" not in run("nft", "list", "table", "ip", "nft_forward")
            exchange(neighbor, "old")
            print("PASS: literal-IP conversion and deletion; unrelated session remains connected")
        finally:
            for child in reversed(children):
                child.terminate()
            for child in reversed(children):
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            run("umount", "/etc/hosts")


if __name__ == "__main__":
    main()
