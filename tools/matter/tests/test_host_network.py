"""Independent Matter.js 0.17.9 -> standalone C server, local IPv6 only.

Requires packages from tools/matter/controller/package-lock.json installed in
build/matter-controller. Explicit interface/address; never edits host networking.
"""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

p = argparse.ArgumentParser()
p.add_argument("--exe", required=True)
p.add_argument("--node", default="node")
p.add_argument("--modules", default="build/matter-controller/node_modules")
p.add_argument("--interface", type=int, required=True)
p.add_argument("--ipv6", required=True)
p.add_argument("--runtime", default="")
p.add_argument("--valgrind", action="store_true")
a = p.parse_args()
run = Path("build") / ("host-network-" + uuid.uuid4().hex)
run.mkdir()
env = dict(os.environ, PATH=(a.runtime + os.pathsep if a.runtime else "") + os.environ["PATH"],
           ASAN_OPTIONS="halt_on_error=1:detect_leaks=" + ("0" if os.name == "nt" else "1"), UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
js = [a.node, "tools/matter/tests/host_controller.mjs", a.modules]
subprocess.run(js + ["credentials", str(run / "credentials")], check=True, env=env, timeout=30)
base = [str(Path(a.exe).resolve()), "--interface", str(a.interface), "--credentials", str(run / "credentials"),
        "--state", str(run / "state.tlv")]
for mode in ("commission", "reconnect"):
    outpath, errpath = run / (mode + ".node.log"), run / (mode + ".node.err")
    with outpath.open("w") as out, errpath.open("w") as err:
        command = base + ["--seconds", "90" if a.valgrind else "40"]
        if a.valgrind:
            command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all", "--track-origins=yes",
                       "--errors-for-leak-kinds=definite,indirect,possible", "--error-exitcode=99",
                       "--log-file=" + str(run / (mode + ".valgrind.log")), *command]
        node = subprocess.Popen(command, stdout=out, stderr=err, env=env)
        try:
            deadline = time.monotonic() + 30
            while "NODE instance=" not in outpath.read_text() and time.monotonic() < deadline:
                if node.poll() is not None:
                    raise AssertionError(errpath.read_text())
                time.sleep(.05)
            banner = next(line for line in outpath.read_text().splitlines() if line.startswith("NODE "))
            port = int(next(field[5:] for field in banner.split() if field.startswith("port=")))
            assert ("mode=CM1" if mode == "commission" else "mode=CM0") in banner, banner
            # Noise must not grant access, poison the shared socket, or stop it.
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as noise:
                for packet in (b"\0", bytes(range(32)), b"\0\xff\xff\0" + bytes(28)):
                    noise.sendto(packet, (a.ipv6, port, 0, a.interface))
            with (run / (mode + ".controller.log")).open("w") as log:
                result = subprocess.run(js + [mode, a.ipv6 + "%" + str(a.interface), str(port), run.name],
                                        stdout=log, stderr=subprocess.STDOUT, env=env, timeout=90)
            controller = (run / (mode + ".controller.log")).read_text()
            assert result.returncode == 0, controller[-4000:]
            assert "PASS CASE EPM/EEM Read" in controller and "PASS timed ECM" in controller
            assert "PASS full-profile wildcard Subscribe" in controller
            assert node.wait(timeout=100) == 0, errpath.read_text()
            assert "STOPPED" in outpath.read_text() and "result=0" in outpath.read_text()
            assert not errpath.read_text(), errpath.read_text()
        finally:
            if node.poll() is None:
                node.kill()  # Only the child this test created, after failure.
                node.wait()
assert (run / "state.tlv").stat().st_size > 0
print("PASS independent commissioning + CASE Read/TimedWrite/Subscribe/ECM + durable restart + ingress noise + stop:", run)
