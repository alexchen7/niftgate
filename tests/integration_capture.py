"""Real NFLOG tests; run only with unshare --mount --net python3 this_file.py."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nft_forward.capture import configure
from nft_forward.capture_store import files, records
from nft_forward.config import load_settings
from nft_forward.nft import write_and_apply
from nft_forward.state import State


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, check=True).stdout.strip()


def main():
    for ns in ("net", "mnt"):
        assert os.readlink(f"/proc/self/ns/{ns}") != os.readlink(f"/proc/1/ns/{ns}"), "requires isolated namespace"
    run("mount", "--make-rprivate", "/")
    run("ip", "link", "set", "lo", "up")
    run("sysctl", "-w", "net.ipv4.ip_forward=1")
    children = []
    with tempfile.TemporaryDirectory(prefix="niftgate-capture-test-") as folder:
        root = Path(folder)
        cfg = root / "config.json"
        cfg.write_text(json.dumps({"paths": {"state_db": str(root / "state.db"), "audit_log": str(root / "audit.jsonl"),
                                             "nft_conf": str(root / "nft.conf"), "ip_cache": str(root / "cache")}}))
        settings = load_settings(cfg)
        (root / "cache").mkdir()
        conn = sqlite3.connect(root / "cache/geoip.db")
        conn.execute("CREATE TABLE ranges(start INTEGER PRIMARY KEY,end INTEGER,geo TEXT,isp TEXT)")
        for suffix, country in ((2, "China"), (3, "United Kingdom"), (4, "Australia")):
            ip = int(ipaddress.IPv4Address(f"10.251.0.{suffix}"))
            conn.execute("INSERT INTO ranges VALUES(?,?,?,?)", (ip, ip, country, "Test ISP"))
        conn.commit()
        conn.close()

        def namespace(name, subnet):
            child = subprocess.Popen(["unshare", "--net", "sleep", "300"])
            children.append(child)
            for _ in range(100):
                if os.readlink(f"/proc/{child.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                    break
                time.sleep(.01)
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
            client, interface = namespace("ngc", "10.251.0")
            server, _ = namespace("ngs", "10.252.0")
            for suffix in (3, 4):
                run(*client, "ip", "addr", "add", f"10.251.0.{suffix}/24", "dev", interface)
            code = '''
import socketserver,threading,time
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request; sock.sendto(data,self.client_address)
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(1024)
            if not data: break
            self.request.sendall(data)
for cls,handler in [(socketserver.ThreadingUDPServer,UDP),(socketserver.ThreadingTCPServer,TCP)]:
    srv=cls(('10.252.0.2',58002),handler)
    threading.Thread(target=srv.serve_forever,daemon=True).start()
print('ready',flush=True); time.sleep(300)
'''
            echo = subprocess.Popen([*server, sys.executable, "-u", "-c", code], stdout=subprocess.PIPE, text=True)
            children.append(echo)
            assert echo.stdout.readline().strip() == "ready"
            state = State(settings.paths.state_db)
            state.add_rule(58001, "10.252.0.2", 58002)
            state.add_rule(58003, "10.252.0.2", 58002, open_access=True)
            state.add_allow("public", "10.251.0.3/32", "manual", 32)
            write_and_apply(settings, state)
            code = '''
import socket,sys
s=socket.socket(); s.bind(('10.251.0.3',0)); s.settimeout(3); s.connect(('10.251.0.1',58001)); print('ready',flush=True)
for line in sys.stdin:
    s.sendall(line.strip().encode()); print(s.recv(1024).decode(),flush=True)
'''
            persistent = subprocess.Popen([*client, sys.executable, "-u", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            children.append(persistent)
            assert persistent.stdout.readline().strip() == "ready"

            def exchange():
                persistent.stdin.write("keep-alive\n")
                persistent.stdin.flush()
                assert persistent.stdout.readline().strip() == "keep-alive"

            def udp(suffix, port=58001, count=1):
                code = '''
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],0)); s.settimeout(.3)
for i in range(int(sys.argv[3])): s.sendto(b'capture-fixture-payload',('10.251.0.1',int(sys.argv[2])))
try: print(s.recv(1024).decode())
except socket.timeout: print('BLOCKED')
'''
                return run(*client, sys.executable, "-c", code, f"10.251.0.{suffix}", str(port), str(count))

            def all_records():
                results = []
                for row in files(settings)["rows"]:
                    first = records(settings, row["id"])
                    for page in range(1, first["pages"] + 1):
                        results += records(settings, row["id"], page, first["anchor"])["rows"]
                return results

            def setup(patch):
                configure(settings, patch, check_service=False)
                time.sleep(4)
                exchange()

            setup({"enabled": True, "ports": [58001], "countries": ["CN"]})
            log = (root / "worker.log").open("w+")
            worker = subprocess.Popen([sys.executable, "-u", "-m", "nft_forward.cli", "--config", str(cfg), "run-capture"],
                                      cwd=Path(__file__).resolve().parents[1], stdout=log, stderr=log)
            children.append(worker)
            time.sleep(3)
            assert udp(2) == "BLOCKED"
            assert udp(4) == "BLOCKED"
            assert udp(3) == "capture-fixture-payload"
            assert udp(2, 58003) == "capture-fixture-payload"
            for _ in range(12):
                captured = all_records()
                if captured:
                    break
                time.sleep(1)
            if not captured:
                log.flush()
                raise AssertionError((root / "worker.log").read_text() + "\n" + run("nft", "list", "table", "ip", "nft_forward"))
            assert {r["source_ip"] for r in captured} == {"10.251.0.2"}
            assert {r["scope"] for r in captured} == {"blocked"}
            assert all(r["destination_port"] == 58001 for r in captured)
            print("PASS: real blocked-only NFLOG capture, country filtering, unselected/allowed traffic excluded", flush=True)

            before = run("nft", "-a", "list", "table", "ip", "nft_forward").splitlines()[0]
            setup({"countries": ["GB", "AU"]})
            assert before == run("nft", "-a", "list", "table", "ip", "nft_forward").splitlines()[0]
            assert udp(4) == "BLOCKED"
            time.sleep(2)
            assert any(r["country"] == "AU" for r in all_records())
            setup({"scope": "all", "countries": []})
            assert udp(3) == "capture-fixture-payload"
            assert udp(2) == "BLOCKED"
            exchange()
            time.sleep(2)
            captured = all_records()
            assert any(r["scope"] == "all" and r["country"] == "GB" and r["protocol"] == "TCP" for r in captured)
            assert any(r["scope"] == "all" and r["country"] == "GB" and r["protocol"] == "UDP" for r in captured)
            print("PASS: all-incoming captures established TCP/UDP; country-only changes do not reload nft; existing connection survives", flush=True)

            # A crashed collector must restart without interfering with forwarding.
            pid = int(run("pgrep", "-P", str(worker.pid)))
            os.kill(pid, 9)
            time.sleep(7)
            assert worker.poll() is None
            before_count = len(all_records())
            assert udp(2) == "BLOCKED"
            exchange()
            time.sleep(2)
            assert len(all_records()) > before_count
            print("PASS: tcpdump crash recovers automatically; forwarding remains intact", flush=True)

            setup({"scope": "blocked", "rate_pps": 10})
            assert udp(2, count=300) == "BLOCKED"
            counters = run("nft", "-j", "list", "table", "ip", "nft_forward")
            data = json.loads(counters)
            counted = {x["counter"]["name"]: x["counter"]["packets"] for x in data["nftables"] if "counter" in x}
            assert counted["capture_seen"] >= 300
            assert 0 < counted["capture_sent"] < 100
            print("PASS: rate-limited copies never rate-limit firewall drops", flush=True)

            setup({"enabled": False})
            count = len(all_records())
            assert udp(2) == "BLOCKED"
            time.sleep(2)
            assert len(all_records()) == count
            assert "packet_capture" not in run("nft", "list", "table", "ip", "nft_forward")
            for file in files(settings)["rows"]:
                run("tcpdump", "-n", "-r", file["path"])
                assert "capture-fixture-payload" not in json.dumps(records(settings, file["id"]))
            state.delete_rule(58001)
            write_and_apply(settings, state)
            state.close()
            assert "58001" not in run("nft", "list", "table", "ip", "nft_forward")
            assert udp(2, 58003) == "capture-fixture-payload"
            print("PASS: disable/delete cleanup, readable PCAPs, payload-free metadata, unrelated forwarding intact", flush=True)
        finally:
            for child in reversed(children):
                child.terminate()
            for child in reversed(children):
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    main()
