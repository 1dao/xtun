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
        def call(*args):return subprocess.run([str(BIN),*map(str,args)],cwd=folder,text=True,capture_output=True)
        assert call("keygen",key).returncode==0
        original=key.read_bytes()
        assert len(original)==64
        assert call("keygen",key).returncode!=0 and key.read_bytes()==original
        base=dict(endpoint="192.0.2.2",identity="test-peer",psk=original.decode(),address="10.77.0.2",peer_address="10.77.0.1")
        def check(changes,expected,mode="client"):
            config=base|changes
            def encode(value):
                if isinstance(value,list): return ", ".join(value)
                if isinstance(value,bool): return str(value).lower()
                return str(value)
            path=folder/f"{mode}.cfg"
            path.write_text("".join(f"{k}={encode(v)}\n" for k,v in config.items()))
            result=call(mode,"--check")
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
        check({"PostUp":"touch hook-ran; false","PostDown":"touch hook-ran"},not windows,"server")
        check({"PostUp":"touch hook-ran"},False)
        assert not (folder/"hook-ran").exists()
        check({"full_tunnel":True},windows)
        check({"full_tunnel":True,"dns":"1.1.1.1"},windows)
        check({"full_tunnel":True,"dns":"192.0.2.2"},False)
        check({"full_tunnel":True,"peer_address":"192.0.2.2"},False)
        check({"full_tunnel":True,"routes":["198.19.0.0/24"]},False)
        check({"full_tunnel":True,"bind":"192.0.2.3"},False)
        check({"full_tunnel":True},False,"server")
        check({"full_tunnel":"sometimes"},False)
        check({"dns":"1.1.1.1"},False)
        path = folder / "client.cfg"
        work = "".join(f"work.{k}={v}\n" for k, v in base.items())
        personal = "".join(f"personal.{k}={v}\n" for k, v in
                           (base | {"endpoint":"203.0.113.1", "psk":"invalid"}).items())
        path.write_text("tags=work, personal\n" + work + personal)
        assert call("client", "--tag", "work", "--check").returncode == 0
        assert call("client", "--tag", "personal", "--check").returncode != 0
        assert call("client", "--tag", "unknown", "--check").returncode != 0
        assert call("client", "--check").returncode != 0
        assert call("client", path, "--tag", "work", "--check").returncode != 0
        (folder / "server.cfg").write_bytes(path.read_bytes())
        assert call("server", "--check").returncode != 0
        path.write_text("tags=work\n" + work)
        assert call("client", "--check").returncode == 0
        path.write_text("tags=work,work\n" + work)
        assert call("client", "--tag", "work", "--check").returncode != 0
        # Untagged fields must never fill missing fields in the selected block.
        path.write_text("tags=work\nidentity=test-peer\n" + work.replace("work.identity=test-peer\n", ""))
        assert call("client", "--tag", "work", "--check").returncode != 0
        path.write_text("tags=work\npsk=" + original.decode() + "\n" +
                        work.replace("work.psk=" + original.decode() + "\n", ""))
        assert call("client", "--tag", "work", "--check").returncode == 0
        path.write_text(path.read_text() + "work.psk=invalid\n")
        assert call("client", "--tag", "work", "--check").returncode != 0
        check({"psk":"not-a-secret-key"},False)
        print("PASS CLI/configuration validation, tag isolation, split-route guards, and key handling")

if __name__=="__main__":main()
