"""Independent DNS-SD acceptance using python-zeroconf 0.147.0.

No implementation wire decoder/encoder is imported. Explicit local interface;
no firewall changes. Node processes terminate themselves and send goodbyes.
"""
import argparse
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from importlib.metadata import version
from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf


class Listener(ServiceListener):
    def __init__(self):
        self.added = set()
        self.removed = set()
        self.lock = threading.Lock()

    def add_service(self, zc, type_, name):
        with self.lock:
            self.added.add((type_, name))

    def update_service(self, zc, type_, name):
        self.add_service(zc, type_, name)

    def remove_service(self, zc, type_, name):
        with self.lock:
            self.removed.add((type_, name))

    def wait(self, entries, removed=False, timeout=6):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self.lock:
                if entries <= (self.removed if removed else self.added):
                    return
            time.sleep(0.05)
        raise AssertionError(f"Missing {'removals' if removed else 'discoveries'}: {entries}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--interface", type=int, required=True)
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ipv6", required=True)
    parser.add_argument("--mdns-ipv6", action="store_true")
    args = parser.parse_args()
    assert version("zeroconf") == "0.147.0", "Use the pinned independent oracle"
    processes = []
    zc = None
    browser = None
    try:
        for duration, operational in ((9, False), (17, False), (13, True)):
            cmd = [os.path.abspath(args.exe), "--interface", str(args.interface), "--seconds", str(duration)]
            if operational:
                cmd.append("--operational-fixture")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            processes.append((proc, None))
            line = proc.stdout.readline().strip()
            match = re.fullmatch(r"NODE instance=(\S+) service=(\S+) host=(\S+) port=(\d+) interface=(\d+) mode=(\S+)", line)
            assert match, line + proc.stdout.read()
            instance, type_, host, port, index, mode = match.groups()
            info = dict(name=instance + "." + type_, type=type_, host=host, port=int(port), mode=mode)
            processes[-1] = (proc, info)
        # A fresh querier after both unsolicited announcements proves responding
        # to actual network queries rather than only local publisher registration.
        time.sleep(3)
        zc = Zeroconf(interfaces=[args.interface] if args.mdns_ipv6 else [args.ipv4],
                      ip_version=IPVersion.V6Only if args.mdns_ipv6 else IPVersion.V4Only)
        listener = Listener()
        types = ["_matterc._udp.local.", "_L3840._sub._matterc._udp.local.",
                 "_S15._sub._matterc._udp.local.", "_matter._tcp.local.",
                 "_I87E1B004E235A130._sub._matter._tcp.local.", "_CM._sub._matterc._udp.local."]
        browser = ServiceBrowser(zc, types, listener)
        for proc, item in processes:
            expected_types = types[:3] if item["mode"] == "CM0" else types[3:5]
            listener.wait({(t, item["name"]) for t in expected_types})
            info = zc.get_service_info(item["type"], item["name"], timeout=2500)
            assert info is not None and info.server.upper() == item["host"].upper()
            assert info.port == item["port"]
            assert ipaddress.IPv6Address(args.ipv6).packed in info.addresses_by_version(IPVersion.V6Only)
            expected = {b"D": b"3840", b"CM": b"0"} if item["mode"] == "CM0" else {b"SII": b"500"}
            assert info.properties == expected, info.properties
            if item["mode"] == "CM0":
                assert re.fullmatch(r"[0-9A-F]{16}\._matterc\._udp\.local\.", item["name"])
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"M12a ingress probe", (args.ipv6, info.port, 0, args.interface))
        first, first_info = processes[0]
        output = first.communicate(timeout=12)[0]
        assert first.returncode == 0 and "PUBLISHED" in output and "rx_packets=1 result=0" in output, output
        assert "import_mWh=1000 export_mWh=500" in output, output
        listener.wait({(t, first_info["name"]) for t in types[:3]}, removed=True)
        # Stopping one publisher must not withdraw the other on the same host.
        assert processes[1][0].poll() is None
        assert zc.get_service_info(processes[1][1]["type"], processes[1][1]["name"], timeout=2000) is not None
        for proc, item in processes[1:]:
            output = proc.communicate(timeout=20)[0]
            assert proc.returncode == 0 and "PUBLISHED" in output and "rx_packets=1 result=0" in output, output
            listener.wait({(item["type"], item["name"])}, removed=True)
        assert processes[0][1]["name"] != processes[1][1]["name"]
        with listener.lock:
            assert not any(t == types[5] and name in {p[1]["name"] for p in processes} for t, name in listener.added)
        print("PASS independent zeroconf: late query/resolve, commissionable/operational/subtypes, TXT/SRV/AAAA, discovered IPv6 UDP, model samples, isolated publishers and goodbye")
    finally:
        if browser:
            browser.cancel()
        if zc:
            zc.close()
        for proc, _ in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()
