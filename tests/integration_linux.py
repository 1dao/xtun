#!/usr/bin/env python3
"""Root-only, isolated TUN/forwarding/NAT acceptance. Host routes stay untouched."""
import hashlib
import os
import re
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("XTUN_BIN", str(ROOT / "bin/xtun"))).resolve()
PORT = int(os.environ.get("XTUN_TEST_PORT", "51215"))
ARQ = int(os.environ.get("XTUN_TEST_ARQ", "0"))
ARQ_LOG = int(os.environ.get("XTUN_TEST_ARQ_LOG", "0"))

def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}{result.stderr}")
    return result

def main():
    if os.geteuid() != 0:
        raise SystemExit("run as root (network namespaces are required)")
    tag = str(os.getpid())
    namespaces = ["xtun-c-" + tag, "xtun-s-" + tag, "xtun-t-" + tag]
    client, server, target = namespaces
    created, processes, logs = [], [], []
    temp = tempfile.TemporaryDirectory(prefix="xtun-", dir=ROOT / "build")
    directory = Path(temp.name)
    def ns(name, *args, **kwargs): return run("ip", "netns", "exec", name, *args, **kwargs)
    def spawn(name, args, filename):
        log = open(directory / filename, "w+")
        logs.append(log)
        p = subprocess.Popen(["ip", "netns", "exec", name, *map(str, args)],
                             cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        processes.append(p)
        return p, log
    def contents(log):
        log.flush()
        return Path(log.name).read_text()
    try:
        for name in namespaces:
            run("ip", "netns", "add", name); created.append(name)
            ns(name, "ip", "link", "set", "lo", "up")
        for suffix, left, right, a, b in [
            ("a", client, server, "192.0.2.1/30", "192.0.2.2/30"),
            ("b", server, target, "198.19.0.1/24", "198.19.0.2/24"),
        ]:
            first, second = "xc"+suffix+tag, "xs"+suffix+tag
            # Create directly inside a test namespace: no host link survives errors.
            ns(left, "ip", "link", "add", first, "type", "veth", "peer", "name", second)
            ns(left, "ip", "link", "set", second, "netns", right)
            for name, interface, address in [(left,first,a),(right,second,b)]:
                ns(name, "ip", "addr", "add", address, "dev", interface)
                ns(name, "ip", "link", "set", interface, "up")
        run(str(BIN), "keygen", str(directory / "peer.key"))
        def config(path, **values):
            values.update(identity="integration-peer", psk=(directory/"peer.key").read_text(), run_seconds=90,
                          session_seconds=30, arq=ARQ, arq_log=ARQ_LOG)
            entries = [f"{key}={','.join(value) if isinstance(value,list) else value}"
                       for key, value in values.items()]
            path.write_text("\n".join(entries)+"\n")
        server_settings = dict(address="10.77.0.1", peer_address="10.77.0.2",
                               bind="192.0.2.2", port=PORT, name="xtun0", local_networks=["198.19.0.0/24"])
        config(directory/"server.cfg", **server_settings,
               PostUp="touch hook-marker; false; touch hook-unexpected", PostDown="rm -f hook-marker; touch hook-cleaned")
        failed, failed_log = spawn(server,[BIN,"server"],"failed-hook.log")
        assert failed.wait(timeout=8) != 0 and "PostUp failed" in contents(failed_log)
        assert (directory/"hook-cleaned").exists()
        assert not (directory/"hook-marker").exists() and not (directory/"hook-unexpected").exists()
        assert "xtun0" not in ns(server,"ip","-o","link","show").stdout
        config(directory/"server.cfg", **server_settings,
               PostUp="nft -f hook.nft", PostDown="nft delete table ip xtun_test")
        config(directory/"client.cfg", address="10.77.0.2", peer_address="10.77.0.1",
               bind="192.0.2.1", endpoint="192.0.2.2", port=PORT, name="xtun0", routes=["198.19.0.0/24"], mtu=1330)
        ns(server,"sysctl","-q","-w","net.ipv4.ip_forward=1")
        (directory/"hook.nft").write_text("table ip xtun_test {\nchain postrouting {\ntype nat hook postrouting priority srcnat;\nip saddr 10.77.0.2 ip daddr 198.19.0.0/24 masquerade\n}\n}\n")
        sp, sl = spawn(server,[BIN,"server"],"server.log")
        cp, cl = spawn(client,[BIN,"client"],"client.log")
        deadline = time.monotonic()+15
        while "READY " not in contents(sl) or "READY " not in contents(cl):
            if time.monotonic()>deadline or sp.poll() is not None or cp.poll() is not None:
                raise AssertionError("tunnel did not become ready\n"+contents(sl)+contents(cl))
            time.sleep(.05)
        print("PASS real TUN adapters and encrypted READY", flush=True)
        assert f"arq={ARQ}" in contents(sl) and f"arq={ARQ}" in contents(cl)
        for name, log in ((client, cl), (server, sl)):
            assert "mtu=1330 " in contents(log), contents(log)
            assert '"mtu":1330' in ns(name,"ip","-j","link","show","xtun0").stdout.replace(" ", "")
        ns(client,"ping","-n","-c","1","-W","2","-M","do","-s","1302","10.77.0.1")
        print("PASS asymmetric MTU negotiation, both real TUN MTUs and maximum-size DF packet", flush=True)
        ns(client,"ping","-n","-c","3","-W","2","10.77.0.1")
        print("PASS tunnel-address ICMP",flush=True)
        ns(client,"ping","-n","-c","3","-W","2","198.19.0.2")
        ns(client,"ping","-n","-c","1","-W","2","-s","3000","198.19.0.2")
        print("PASS isolated forwarding/NAT, including fragmented IPv4",flush=True)
        if ARQ:
            # Only test-owned namespace links are affected; the host and live
            # server remain untouched. Exercise real encrypted loss in both directions.
            ns(client,"tc","qdisc","add","dev","xca"+tag,"root","netem","loss","3%","delay","10ms")
            ns(server,"tc","qdisc","add","dev","xsa"+tag,"root","netem","loss","3%","delay","10ms")
        # Distinct endpoints test TCP delivery and UDP datagram semantics through NAT.
        tcp_server = """import socket,hashlib
s=socket.socket();s.bind(('198.19.0.2',9001));s.listen();c,a=s.accept();h=hashlib.sha256()
while True:
 d=c.recv(65536)
 if not d:break
 h.update(d)
c.sendall(h.hexdigest().encode());c.close();s.close()
"""
        udp_server = """import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.19.0.2',9002));s.settimeout(30)
for i in range(20):
 d,a=s.recvfrom(2048);s.sendto(d,a)
"""
        tp, _ = spawn(target,["python3","-c",tcp_server],"tcp.log")
        up, _ = spawn(target,["python3","-c",udp_server],"udp.log")
        time.sleep(.15)
        client_test = """import socket,hashlib,os
p=os.urandom(2*1024*1024);s=socket.create_connection(('198.19.0.2',9001),10);s.settimeout(20);s.sendall(p);s.shutdown(socket.SHUT_WR)
r=b''
while len(r)<64:
 d=s.recv(64-len(r))
 if not d:break
 r+=d
assert r.decode()==hashlib.sha256(p).hexdigest();s.close()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(2)
for i in range(20):
 p=os.urandom(1000);u.sendto(p,('198.19.0.2',9002));d,a=u.recvfrom(2048);assert d==p
u.close()
"""
        before=time.monotonic(); ns(client,"python3","-c",client_test)
        tp.wait(timeout=5);up.wait(timeout=5)
        assert tp.returncode==up.returncode==0
        print(f"PASS TCP 2 MiB SHA-256 and 20 binary UDP round trips ({time.monotonic()-before:.2f}s)",flush=True)
        if ARQ:
            for name, interface in ((client,"xca"+tag),(server,"xsa"+tag)):
                ns(name,"tc","qdisc","del","dev",interface,"root")
        # Test a clean session renewal without re-installing/removing existing routes.
        deadline = time.monotonic()+40
        while contents(sl).count("READY ") < 2 or contents(cl).count("READY ") < 2:
            if time.monotonic()>deadline or sp.poll() is not None or cp.poll() is not None:
                raise AssertionError("session renewal failed\n"+contents(sl)+contents(cl))
            time.sleep(.1)
        ns(client,"ping","-n","-c","1","-W","2","198.19.0.2")
        print("PASS fresh ECDHE session after lifetime expiry; routes preserved",flush=True)
        # A replacement client can grow/shrink the server's MTU across sessions.
        for ceiling in (0, 1280):
            cp.send_signal(signal.SIGTERM); assert cp.wait(timeout=8) == 0
            ready_count = contents(sl).count("READY ")
            config(directory/"client.cfg", address="10.77.0.2", peer_address="10.77.0.1",
                   bind="192.0.2.1", endpoint="192.0.2.2", port=PORT, name="xtun0",
                   routes=["198.19.0.0/24"], mtu=ceiling)
            cp, cl = spawn(client,[BIN,"client"],f"client-mtu-{ceiling}.log")
            deadline = time.monotonic()+15
            while "READY " not in contents(cl) or contents(sl).count("READY ") <= ready_count:
                assert time.monotonic() < deadline and sp.poll() is None and cp.poll() is None
                time.sleep(.05)
            selected = int(re.search(r"READY .* mtu=(\d+)", contents(cl))[1])
            assert selected > 1330 if ceiling == 0 else selected == 1280
            for name in (client, server):
                assert f'"mtu":{selected}' in ns(name,"ip","-j","link","show","xtun0").stdout.replace(" ", "")
            ns(client,"ping","-n","-c","1","-W","2","-M","do","-s",str(selected-28),"198.19.0.2")
        print("PASS reconnect MTU growth/shrink, adapter updates and maximum-size DF forwarding",flush=True)
        # Normal shutdown must remove the adapter and only this process's routes.
        for p in [cp,sp]: p.send_signal(signal.SIGTERM)
        for p in [cp,sp]: assert p.wait(timeout=8)==0
        assert "xtun_test" not in ns(server,"nft","list","tables").stdout
        for name in [client,server]:
            assert "xtun0" not in ns(name,"ip","-o","link","show").stdout
            assert "10.77." not in ns(name,"ip","-4","route","show").stdout
        print("PASS normal shutdown removes owned routes and adapters",flush=True)
        for log in [sl,cl]:
            text=contents(log)
            stats=next(line for line in text.splitlines() if line.startswith('STATS '))
            counters={key:int(value) for key,value in (field.split('=') for field in stats.split()[1:])}
            assert sum(value for key,value in counters.items() if key.startswith('drop_'))==counters['drops']
            # IPv4-only adapters intentionally reject other host-generated IP
            # traffic (such as IPv6 control packets); keep those counts visible.
            print(text.strip())
        if ARQ:
            text="\n".join(contents(log) for log in logs)
            repairs=sum(int(n) for n in re.findall(r"ARQ_STATS .*?retransmits=(\d+)",text))
            filled=sum(int(n) for n in re.findall(r"ARQ_STATS .*?gap_filled=(\d+)",text))
            assert repairs > 0 and filled > 0, text
            print(f"PASS ARQ with bidirectional 3% loss: retransmits={repairs} gap_filled={filled}",flush=True)
            if ARQ_LOG:
                for event in ("gap_detect","timer_start","timer_expire","timer_arm","nack_sent",
                              "nack_received","repair_sent","gap_filled","timer_cancel"):
                    assert f"event={event} " in text, event
                print("PASS real TUN ARQ event logs cover gaps, timers, feedback, repairs and cancellation",flush=True)
        print("LINUX INTEGRATION PASSED",flush=True)
    finally:
        for p in processes:
            if p.poll() is None: p.terminate()
        for p in processes:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        for log in logs:log.close()
        for name in reversed(created):
            subprocess.run(["ip","netns","del",name],check=False,capture_output=True)
        temp.cleanup()

if __name__ == "__main__":main()
