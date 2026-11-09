"""CLI validation, no sockets/adapters/routes. Works on Windows and Linux."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("XTUN_BIN", str(ROOT/"bin"/("xtun.exe" if os.name=="nt" else "xtun")))).resolve()

def main():
    with tempfile.TemporaryDirectory(dir=ROOT/"build",prefix="config-") as folder:
        folder=Path(folder)
        key=folder/"peer.key"
        def call(*args):return subprocess.run([str(BIN),*map(str,args)],text=True,capture_output=True)
        assert call("keygen",key).returncode==0
        original=key.read_bytes()
        assert len(original)==64
        assert call("keygen",key).returncode!=0 and key.read_bytes()==original
        base=dict(endpoint="192.0.2.2",identity="test-peer",psk_file="peer.key",address="10.77.0.2",peer_address="10.77.0.1")
        def check(changes,expected,mode="client"):
            config=base|changes
            def encode(value):
                if isinstance(value,list): return ", ".join(value)
                if isinstance(value,bool): return str(value).lower()
                return str(value)
            path=folder/"config.cfg"
            path.write_text("".join(f"{k}={encode(v)}\n" for k,v in config.items()))
            result=call(mode,path,"--check")
            assert (result.returncode==0)==expected,(changes,result.stdout,result.stderr)
            assert original.decode() not in result.stdout+result.stderr
        check({},True)
        check({"routes":["198.19.0.0/24", "203.0.113.0/24"]},True)
        check({"routes":"198.19.0.0/24,"},False)
        check({"routes":["0.0.0.0/0"]},False)
        check({"routes":["192.0.2.0/24"]},False)
        check({"routes":["10.77.0.0/24"]},False)
        check({"routes":["198.19.0.1/24"]},False)
        check({"address":"10.77.0.1"},False)
        check({"port":65536},False)
        check({"name":"bad;name"},False)
        check({"identity":""},False)
        check({"local_networks":["198.19.0.0/24"]},False)
        check({"local_networks":["198.19.0.0/24"]},True,"server")
        check({"local_networks":["0.0.0.0/0"]},True,"server")
        windows = os.name == "nt"
        check({"full_tunnel":True},windows)
        check({"full_tunnel":True,"dns":"1.1.1.1"},windows)
        check({"full_tunnel":True,"dns":"192.0.2.2"},False)
        check({"full_tunnel":True,"peer_address":"192.0.2.2"},False)
        check({"full_tunnel":True,"routes":["198.19.0.0/24"]},False)
        check({"full_tunnel":True,"bind":"192.0.2.3"},False)
        check({"full_tunnel":True},False,"server")
        check({"full_tunnel":"sometimes"},False)
        check({"dns":"1.1.1.1"},False)
        key.write_text("not-a-secret-key")
        check({},False)
        print("PASS CLI/configuration validation, split-route guards, relative keys and exclusive key creation")

if __name__=="__main__":main()
