"""Real STM32 TLS engine/RNG/UTC against an OpenSSL MemoryBIO peer over UART.

Flash the local dmtls/tlsprobe packages first, and upload the fixture ca.pem
and other.pem to /. The UART is the test transport; this does not claim to
exercise dmtcp or HTTPS. This harness restores PC UTC and the UTC unit.
"""
import argparse
import datetime
from pathlib import Path
import re
import select
import ssl
import sys
import time

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--boot-dir',type=Path,required=True)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--port',default='/dev/ttyACM0')
args=parser.parse_args()
sys.path.insert(0,str(args.boot_dir/'scripts'))
from ymodem_send import Link
link=Link(args.port,921600)
ansi=re.compile(rb'\x1b\[[0-9;]*[A-Za-z]')

def command(text,timeout=60):
    marker=b'DMTLS_COMMAND_DONE_627'
    link.write(text.encode()+b'\necho '+marker+b'\n')
    received=b'';end=time.monotonic()+timeout
    while time.monotonic()<end:
        received+=link.drain(.15)
        if marker in received.splitlines():
            out=ansi.sub(b'',received).decode(errors='replace').replace('\r','')
            print(out,flush=True);return out
    raise TimeoutError(text)

def pc_utc():command('rtc set '+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'))

def probe(label,version,hostname='tls.test',ca='/ca.pem',expected=0,flag=0):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ctx.maximum_version=version
    ctx.load_cert_chain(args.fixtures/'server.pem',args.fixtures/'server.key')
    incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO();peer=ctx.wrap_bio(incoming,outgoing,server_side=True)
    handshake=False;peer_error=None;server_pending=bytearray();buffer=b'';opened=False;data_ok=False
    def progress():
        nonlocal handshake,peer_error
        if peer_error is not None:return
        try:
            if not handshake:peer.do_handshake();handshake=True
            while True:
                data=peer.read(4096)
                if not data:break
                peer.write(data)
        except (ssl.SSLWantReadError,ssl.SSLWantWriteError):pass
        except (ssl.SSLZeroReturnError,ssl.SSLError) as error:peer_error=str(error)
        while outgoing.pending:server_pending.extend(outgoing.read())
    print(f'PROBE {label}',flush=True)
    link.write(f'tlsprobe {hostname} {ca}\n'.encode())
    end=time.monotonic()+65
    while time.monotonic()<end:
        ready,_,_=select.select([link.rfd],[],[],.5)
        if not ready:continue
        import os
        buffer+=os.read(link.rfd,8192)
        while b'\n' in buffer:
            raw,buffer=buffer.split(b'\n',1);line=ansi.sub(b'',raw).replace(b'\r',b'').decode(errors='replace')
            if line.startswith('TLS_OUT '):
                incoming.write(bytes.fromhex(line[8:]));progress()
            elif line=='TLS_INPUT':
                progress();chunk=server_pending[:64];del server_pending[:64]
                link.write(b'I '+chunk.hex().encode()+b'\n')
            elif line.startswith('TLS_DONE '):
                print(line,flush=True)
                match=re.search(r'result=(-?\d+) verify=(\d+)',line);assert match,line
                rc,bits=map(int,match.groups());assert rc==expected,(label,rc,expected,peer_error)
                if flag:assert bits&flag,(label,bits,flag)
                if expected==0:assert opened and data_ok and handshake,(label,opened,data_ok,handshake)
                # TLS_DONE is emitted after terminal flags have been restored;
                # wait for process exit before the next shell command.
                link.drain(.2)
                print(f'PASS {label}',flush=True);return
            elif line.startswith('TLS_'):
                print(line,flush=True)
                if line=='TLS_OPEN':opened=True
                if line=='TLS_DATA_OK':data_ok=True
            elif line:print('UART '+line,flush=True)
    raise TimeoutError(label+' '+repr(buffer[-200:]))

try:
    command('echo DMTLS_BOARD_READY')
    pc_utc()
    result=command('test_dmtls');assert '3/3 passed' in result
    probe('TLS12',ssl.TLSVersion.TLSv1_2)
    probe('TLS13',ssl.TLSVersion.TLSv1_3)
    probe('wrong-hostname',ssl.TLSVersion.TLSv1_3,hostname='wrong.test',expected=-6,flag=2)
    probe('untrusted-CA',ssl.TLSVersion.TLSv1_3,ca='/other.pem',expected=-6,flag=1)
    command('rtc set 2020-01-01T00:00:00')
    probe('future-certificate',ssl.TLSVersion.TLSv1_3,expected=-6,flag=8)
    command('rtc set 2035-01-01T00:00:00')
    probe('expired-certificate',ssl.TLSVersion.TLSv1_3,expected=-6,flag=4)
    pc_utc()
    command('service stop dmutc@rtc')
    try:probe('missing-UTC-source',ssl.TLSVersion.TLSv1_3,expected=-5)
    finally:command('service start dmutc@rtc')
    for name,count in [('test_dmutc','6/6'),('test_dmrtc','12/12'),('test_dmrng','6/6')]:
        assert count+' passed' in command(name)
    print('HARDWARE_TLS_PROBES 7/7 PASS',flush=True)
except BaseException:
    link.write(b'X\n');link.drain(.3)
    raise
finally:
    try:pc_utc();command('service status dmutc@rtc')
    finally:link.close()
