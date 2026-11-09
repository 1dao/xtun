#!/usr/bin/env python3
"""Sustained real-tunnel transfer/telemetry harness; no system network setup."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

CHUNK = 256 * 1024
FILE_BYTES = 64 * 1024 * 1024

def atomic_json(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temp.replace(path)

def make_file(path):
    digest = hashlib.sha256()
    with path.open('wb') as f:
        for _ in range(FILE_BYTES // CHUNK):
            data = os.urandom(CHUNK)
            f.write(data)
            digest.update(data)
    return digest.hexdigest()

def exact(s, n, stop):
    data = bytearray()
    while len(data) < n:
        if stop():
            raise InterruptedError('test finished')
        try:
            block = s.recv(min(CHUNK, n-len(data)))
        except socket.timeout:
            continue
        if not block:
            raise ConnectionError('unexpected EOF')
        data.extend(block)
    return bytes(data)

def send(s, data, stop, counter=None):
    view = memoryview(data)
    while view:
        if stop():
            raise InterruptedError('test finished')
        try:
            n = s.send(view)
        except socket.timeout:
            continue
        if not n:
            raise ConnectionError('socket closed during send')
        if counter:
            counter(n)
        view = view[n:]

def linux_stats(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rfind(')')+2:].split()
    return dict(cpu_seconds=(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'),
                rss_bytes=int(fields[21])*os.sysconf('SC_PAGE_SIZE'))

def windows_stats(process):
    from ctypes import wintypes
    class Memory(ctypes.Structure):
        _fields_ = [('cb',wintypes.DWORD),('faults',wintypes.DWORD)] + [
            (name,ctypes.c_size_t) for name in ['peak_rss','rss','peak_pool','pool',
                                             'peak_nonpaged','nonpaged','pagefile','peak_pagefile','private']]
    class FileTime(ctypes.Structure):
        _fields_ = [('low',wintypes.DWORD),('high',wintypes.DWORD)]
    handle = wintypes.HANDLE(int(process._handle))
    mem = Memory(); mem.cb = ctypes.sizeof(mem)
    psapi = ctypes.WinDLL('psapi',use_last_error=True)
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    if not psapi.GetProcessMemoryInfo(handle,ctypes.byref(mem),mem.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    created, exited, system, user = FileTime(),FileTime(),FileTime(),FileTime()
    if not kernel.GetProcessTimes(handle,ctypes.byref(created),ctypes.byref(exited),ctypes.byref(system),ctypes.byref(user)):
        raise ctypes.WinError(ctypes.get_last_error())
    total = ((system.high<<32)+system.low+(user.high<<32)+user.low)/10_000_000
    return dict(cpu_seconds=total,rss_bytes=mem.rss,private_bytes=mem.private,peak_rss_bytes=mem.peak_rss)

class AttachedWindowsProcess:
    def __init__(self,pid):
        from ctypes import wintypes
        self.pid=pid
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.OpenProcess.restype=wintypes.HANDLE
        self._handle=self.kernel.OpenProcess(0x1000|0x100000,False,pid)
        if not self._handle:raise ctypes.WinError(ctypes.get_last_error())
        self.returncode=None
    def poll(self):
        from ctypes import wintypes
        code=wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(wintypes.HANDLE(self._handle),ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.returncode=None if code.value==259 else code.value
        return self.returncode
    def close(self):
        from ctypes import wintypes
        self.kernel.CloseHandle(wintypes.HANDLE(self._handle))

def serve(args):
    work = args.work.resolve()
    stop = threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    source = work/'download.bin'
    digest = make_file(source)
    atomic_json(work/'server-manifest.json',dict(file_bytes=FILE_BYTES,sha256=digest))
    def handler(s):
        s.settimeout(1)
        try:
            with s:
                while not stop.is_set():
                    command = exact(s,1,stop.is_set)
                    if command == b'U':
                        size = struct.unpack('!Q',exact(s,8,stop.is_set))[0]
                        if size != FILE_BYTES:
                            raise ValueError('invalid upload size')
                        remaining = size
                        h = hashlib.sha256()
                        path = work/f'upload-{threading.get_ident()}.bin'
                        with path.open('wb') as f:
                            while remaining:
                                block = exact(s,min(CHUNK,remaining),stop.is_set)
                                f.write(block); h.update(block); remaining -= len(block)
                        send(s,h.hexdigest().encode(),stop.is_set)
                    elif command == b'D':
                        send(s,struct.pack('!Q',FILE_BYTES)+digest.encode(),stop.is_set)
                        with source.open('rb') as f:
                            while True:
                                block = f.read(CHUNK)
                                if not block: break
                                send(s,block,stop.is_set)
                    else:
                        raise ValueError('unknown transfer command')
        except (OSError,ValueError):
            pass
    def udp():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.bind((args.bind,9002)); s.settimeout(.5)
            while not stop.is_set():
                try:
                    data, address = s.recvfrom(2048)
                    s.sendto(data,address)
                except socket.timeout: pass
    threading.Thread(target=udp,daemon=True).start()
    def monitor():
        previous = None
        with (work/'server-metrics.jsonl').open('w',buffering=1) as log:
            while not stop.is_set():
                try:
                    sample = linux_stats(args.pid); sample['time'] = time.time()
                    if previous:
                        sample['cpu_percent_one_core'] = 100*(sample['cpu_seconds']-previous['cpu_seconds'])/(sample['time']-previous['time'])
                    log.write(json.dumps(sample)+'\n'); previous = sample
                except (OSError,ValueError):
                    stop.set(); break
                stop.wait(5)
    threading.Thread(target=monitor,daemon=True).start()
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((args.bind,9001)); listener.listen(4); listener.settimeout(.5)
        atomic_json(work/'services-ready.json',dict(time=time.time(),pid=os.getpid()))
        while not stop.is_set():
            try:
                s, _ = listener.accept()
                threading.Thread(target=handler,args=(s,),daemon=True).start()
            except socket.timeout: pass

def client(args):
    work = args.work.resolve(); work.mkdir(parents=True,exist_ok=True)
    if not args.attach_pid and os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit('Administrator terminal required to create Wintun')
    state = dict(status='starting',requested_seconds=args.seconds,upload_bytes=0,download_bytes=0,
                 upload_files=0,download_files=0,hash_failures=0,connection_errors=0,
                 udp_sent=0,udp_received=0,udp_duplicates=0,udp_out_of_order=0,udp_lost=0,
                 udp_send_errors=0,udp_receive_errors=0,udp_late=0,udp_unknown=0,udp_invalid=0)
    lock = threading.Lock(); stop = threading.Event(); rtts=[]; hashes=[]
    out = (work/'client.log').open('w')
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0
    process = AttachedWindowsProcess(args.attach_pid) if args.attach_pid else subprocess.Popen(
        [str(args.xtun.resolve()),'client',str(args.config.resolve())],
        stdout=out,stderr=subprocess.STDOUT,creationflags=flags)
    state['xtun_pid'] = process.pid
    atomic_json(work/'progress.json',state)
    started = None
    try:
        until = time.monotonic()+45
        def ready():
            if not args.attach_pid:return 'READY ' in (work/'client.log').read_text(errors='replace')
            try:
                with socket.create_connection((args.host,9001),timeout=1):return True
            except OSError:return False
        while not ready():
            if process.poll() is not None: raise RuntimeError('XTun exited before READY')
            if time.monotonic()>until: raise RuntimeError('XTun handshake timed out')
            time.sleep(.2)
        source = work/'upload.bin'; upload_hash = make_file(source)
        started = time.monotonic(); deadline = started+args.seconds
        state.update(status='running',start_time=time.time(),file_bytes=FILE_BYTES,upload_sha256=upload_hash)
        def finished(): return stop.is_set() or time.monotonic()>=deadline
        def add(name,n):
            with lock: state[name]+=n
        def transfer(direction):
            while not finished():
                try:
                    with socket.create_connection((args.host,9001),timeout=5) as s:
                        s.settimeout(1)
                        while not finished():
                            if direction=='upload':
                                send(s,b'U'+struct.pack('!Q',FILE_BYTES),finished)
                                with source.open('rb') as f:
                                    while True:
                                        block=f.read(CHUNK)
                                        if not block:break
                                        send(s,block,finished,lambda n:add('upload_bytes',n))
                                actual=exact(s,64,finished).decode('ascii'); expected=upload_hash
                            else:
                                send(s,b'D',finished)
                                size=struct.unpack('!Q',exact(s,8,finished))[0]
                                if size!=FILE_BYTES:raise ValueError('bad download size')
                                expected=exact(s,64,finished).decode('ascii'); h=hashlib.sha256()
                                with (work/'download.bin').open('wb') as f:
                                    remaining=size
                                    while remaining:
                                        block=exact(s,min(CHUNK,remaining),finished)
                                        f.write(block);h.update(block);remaining-=len(block);add('download_bytes',len(block))
                                actual=h.hexdigest()
                            if actual!=expected:
                                add('hash_failures',1); raise ValueError('SHA-256 mismatch')
                            with lock:
                                state[direction+'_files']+=1
                                hashes.append(dict(direction=direction,time=time.time(),bytes=FILE_BYTES,sha256=actual))
                except InterruptedError:break
                except (OSError,ValueError) as error:
                    if finished():break
                    with lock:
                        state['connection_errors']+=1;state['last_error']=str(error)
                    stop.wait(.5)
        def udp():
            pending={};expired={};received=set();last=-1;seq=0;next_send=time.monotonic()
            with (work/'udp-events.jsonl').open('w',buffering=1) as events, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                def event(kind,number=None,**fields):
                    events.write(json.dumps(dict(event=kind,sequence=number,time=time.time(),**fields))+'\n')
                s.connect((args.host,9002));s.settimeout(.02)
                while not finished():
                    now=time.monotonic()
                    if now>=next_send:
                        number=seq;seq+=1  # Never reuse an ID after an ambiguous send error.
                        payload=struct.pack('!Q',number)+bytes(992)
                        try:
                            n=s.send(payload)
                            if n!=len(payload):raise OSError('partial datagram send')
                            pending[number]=now;add('udp_sent',1);event('send',number)
                        except OSError as error:
                            add('udp_send_errors',1);event('send_error',number,error=str(error),code=error.errno)
                        next_send=now+.1
                    try:
                        data=s.recv(2048)
                        if len(data)!=1000 or data[8:]!=bytes(992):
                            add('udp_invalid',1);event('invalid',length=len(data));continue
                        number=struct.unpack('!Q',data[:8])[0]
                        if number in received:add('udp_duplicates',1);event('duplicate',number)
                        elif number in pending:
                            elapsed=(time.monotonic()-pending.pop(number))*1000
                            received.add(number);rtts.append(elapsed);add('udp_received',1);event('receive',number,rtt_ms=elapsed)
                            if number<last:add('udp_out_of_order',1)
                            last=max(last,number)
                        elif number in expired:
                            elapsed=(time.monotonic()-expired.pop(number))*1000
                            received.add(number);add('udp_late',1);event('late',number,rtt_ms=elapsed)
                        else:add('udp_unknown',1);event('unknown',number)
                    except socket.timeout:pass
                    except OSError as error:
                        add('udp_receive_errors',1);event('receive_error',error=str(error),code=error.errno)
                    timed_out=[n for n,when in pending.items() if time.monotonic()-when>=5]
                    for n in timed_out:
                        expired[n]=pending.pop(n);add('udp_lost',1);event('timeout',n)
                # Outstanding probes at the deadline are reported separately.
                with lock:state['udp_pending_at_end']=len(pending)
        threads=[threading.Thread(target=transfer,args=(d,),daemon=True) for d in ['upload','download']]
        threads.append(threading.Thread(target=udp,daemon=True))
        for thread in threads:thread.start()
        previous=None
        with (work/'client-metrics.jsonl').open('w',buffering=1) as log:
            while not finished():
                if process.poll() is not None:raise RuntimeError('XTun exited during sustained transfer')
                if not finished() and any(not thread.is_alive() for thread in threads):
                    raise RuntimeError('a transfer or UDP worker exited unexpectedly')
                sample=windows_stats(process) if os.name=='nt' else linux_stats(process.pid)
                sample.update(time=time.time(),elapsed=time.monotonic()-started)
                with lock:sample.update(state)
                if previous:
                    dt=sample['time']-previous['time']
                    sample['cpu_percent_one_core']=100*(sample['cpu_seconds']-previous['cpu_seconds'])/dt
                    for d in ['upload','download']:
                        sample[d+'_mbps']=8*(sample[d+'_bytes']-previous[d+'_bytes'])/dt/1_000_000
                log.write(json.dumps(sample)+'\n');atomic_json(work/'progress.json',sample);previous=sample
                stop.wait(min(5,max(0,deadline-time.monotonic())))
        stop.set()
        for thread in threads:thread.join(timeout=8)
        state['elapsed_seconds']=time.monotonic()-started
        state['integrity_passed']=bool(state['hash_failures']==0 and state['upload_files'] and state['download_files'])
        state['status']='completed' if state['integrity_passed'] and state['udp_received'] else 'failed'
        state['end_time']=time.time()
        if rtts:
            ordered=sorted(rtts)
            state['udp_rtt_ms']=dict(min=min(rtts),mean=sum(rtts)/len(rtts),p95=ordered[int((len(ordered)-1)*.95)],max=max(rtts))
        state['verified_transfers']=hashes
    except BaseException as error:
        state.update(status='failed',error=str(error),end_time=time.time())
        if started:state['elapsed_seconds']=time.monotonic()-started
        stop.set()
    finally:
        if not args.attach_pid and process.poll() is None:
            try:process.send_signal(signal.CTRL_BREAK_EVENT if os.name=='nt' else signal.SIGTERM)
            except OSError:pass
            try:process.wait(timeout=80)
            except subprocess.TimeoutExpired:process.kill();process.wait();state['forced_termination']=True
        out.close();state['xtun_exit_code']=process.returncode
        if args.attach_pid:process.close()
        atomic_json(work/'summary.json',state);atomic_json(work/'progress.json',state)
    print(json.dumps({k:v for k,v in state.items() if k!='verified_transfers'},indent=2),flush=True)
    return 0 if state['status']=='completed' and (args.attach_pid or state['xtun_exit_code']==0) else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='mode',required=True)
    server=sub.add_parser('serve');server.add_argument('--work',type=Path,required=True)
    server.add_argument('--pid',type=int,required=True);server.add_argument('--bind',default='10.77.0.1')
    run=sub.add_parser('client');run.add_argument('--work',type=Path,required=True)
    run.add_argument('--xtun',type=Path);run.add_argument('--config',type=Path)
    run.add_argument('--attach-pid',type=int)
    run.add_argument('--seconds',type=int,default=1800);run.add_argument('--host',default='10.77.0.1')
    args=parser.parse_args()
    return serve(args) if args.mode=='serve' else client(args)

if __name__=='__main__':raise SystemExit(main())
