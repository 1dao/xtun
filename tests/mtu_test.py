"""Authenticated MTU negotiation over loopback UDP; no adapters or routes."""
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("XTUN_BIN", str(ROOT / "bin" / ("xtun.exe" if os.name == "nt" else "xtun")))).resolve()


def main():
    for client_limit, server_limit, loss in ((0, 0, False), (0, 1280, False), (1300, 1320, False), (1400, 0, False), (0, 0, True)):
        with tempfile.TemporaryDirectory(prefix="mtu-", dir=ROOT / "build") as folder:
            folder = Path(folder)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            common = f"identity=mtu-test\npsk={secrets.token_hex(32)}\nrun_seconds=8\n"
            (folder / "server.cfg").write_text(common + f"port={port}\nbind=127.0.0.1\naddress=10.77.0.1\npeer_address=10.77.0.2\nmtu={server_limit}\n")
            relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            relay.bind(("127.0.0.1", 0)); relay.settimeout(.05)
            stop = threading.Event(); dropped = [0, 0]
            def forward():
                client_address = None
                while not stop.is_set():
                    try: data, address = relay.recvfrom(65535)
                    except (socket.timeout, ConnectionResetError): continue
                    direction = int(address[1] == port)
                    if not direction: client_address = address
                    if data[0] == 23 and dropped[direction] < 2:
                        dropped[direction] += 1; continue
                    destination = client_address if direction else ("127.0.0.1", port)
                    if destination: relay.sendto(data, destination)
            thread = threading.Thread(target=forward)
            if loss: thread.start()
            client_port = relay.getsockname()[1] if loss else port
            (folder / "client.cfg").write_text(common + f"port={client_port}\nendpoint=127.0.0.1\naddress=10.77.0.2\npeer_address=10.77.0.1\nmtu={client_limit}\n")
            with open(folder / "server.log", "w+") as log:
                server = subprocess.Popen([str(BIN), "server", "--probe"], cwd=folder, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 4
                    while "LISTEN " not in (folder / "server.log").read_text():
                        assert server.poll() is None and time.monotonic() < deadline
                        time.sleep(.01)
                    client = subprocess.run([str(BIN), "client", "--probe"], cwd=folder, capture_output=True, text=True, timeout=10)
                    assert client.returncode == 0, client.stdout + client.stderr
                    deadline = time.monotonic() + 2
                    while "READY " not in (folder / "server.log").read_text():
                        assert server.poll() is None and time.monotonic() < deadline
                        time.sleep(.01)
                    outputs = (client.stdout, (folder / "server.log").read_text())
                    offers = [int(re.search(r"MTU_OFFER .* offer=(\d+)", out)[1]) for out in outputs]
                    selected = min(offers)
                    for out, offer, limit in zip(outputs, offers, (client_limit, server_limit)):
                        payload = int(re.search(r"dtls_payload=(\d+)", out)[1])
                        assert offer == min(payload - 8, limit or 1400, 1400)
                        assert f"mtu={selected} " in out, out
                    if loss: assert sum(dropped) >= 2
                    print(f"PASS ceilings={client_limit}/{server_limit} offers={offers} negotiated={selected} dropped={dropped}")
                finally:
                    if server.poll() is None: server.terminate()
                    server.wait(timeout=5)
                    stop.set()
                    if loss: thread.join(timeout=2)
                    relay.close()


if __name__ == "__main__":
    main()
