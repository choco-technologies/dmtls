"""Exercise the production engine/backend against independent OpenSSL peers."""
import ctypes as C
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

OK, WANT_READ, WANT_WRITE, PEER_CLOSED = 0, 1, 2, 3
ARGUMENT, MEMORY, STATE, ENTROPY, UTC, CERT, PROTOCOL, TRANSPORT, BUSY, LIMIT, TRUNCATED, TIMEOUT = range(-1,-13,-1)
U8=C.POINTER(C.c_ubyte)
Entropy=C.CFUNCTYPE(C.c_int,C.c_void_p,U8,C.c_size_t)
IO=C.CFUNCTYPE(C.c_int,C.c_void_p,U8,C.c_size_t,C.POINTER(C.c_size_t))
class Platform(C.Structure):
    _fields_=[('entropy',Entropy),('user',C.c_void_p),('heap_limit',C.c_size_t),('max_connections',C.c_uint32)]
class Transport(C.Structure):
    _fields_=[('send',IO),('receive',IO),('user',C.c_void_p)]
class Status(C.Structure):
    _fields_=[('state',C.c_int),('error',C.c_int),('verification_flags',C.c_uint32)]
lib=C.CDLL(sys.argv.pop(1))
for name,args in {
 'initialize':[C.POINTER(Platform)],'shutdown':[],
 'config_create':[C.c_void_p,C.c_size_t,C.POINTER(C.c_void_p)],'config_destroy':[C.c_void_p],
 'connection_create':[C.c_void_p,C.c_char_p,C.POINTER(Transport),C.c_uint32,C.c_uint32,C.POINTER(C.c_void_p)],
 'connection_destroy':[C.c_void_p],'handshake':[C.c_void_p],
 'read':[C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],
 'write':[C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],
 'close':[C.c_void_p],'status':[C.c_void_p,C.POINTER(Status)]}.items():
    fn=getattr(lib,'dmtls_'+name);fn.argtypes=args;fn.restype=C.c_int
lib.test_live_allocations.restype=C.c_size_t
lib.test_utc_offset.argtypes=[C.c_int64]
lib.test_ticks_advance.argtypes=[C.c_uint32]
assert lib.dmod_init(None)==0

class Peer:
    def __init__(self, context, abrupt=False, max_io=97):
        self.socket, server=socket.socketpair()
        self.socket.setblocking(False)
        self.send_calls=self.recv_calls=0
        self.reentrant=None
        self.force_send=None
        self.abrupt=abrupt
        self.errors=[]
        def run():
            try:
                with context.wrap_socket(server,server_side=True) as tls:
                    data=tls.recv(16384)
                    if data: tls.sendall(data)
                    if abrupt:
                        os.close(tls.detach())
                    else:
                        tls.unwrap().close()
            except (ssl.SSLError,OSError) as e:
                self.errors.append(e)
            finally:
                server.close()
        self.thread=threading.Thread(target=run,daemon=True)
        self.thread.start()
        def send(user,data,size,sent):
            sent[0]=0;self.send_calls+=1
            if self.reentrant is not None:self.reentrant()
            if self.force_send is not None:return self.force_send(data,size,sent)
            if self.send_calls%3==0:return WANT_WRITE
            try:sent[0]=self.socket.send(C.string_at(data,min(size,max_io)))
            except BlockingIOError:return WANT_WRITE
            except OSError:return TRANSPORT
            return OK
        def receive(user,data,size,received):
            received[0]=0;self.recv_calls+=1
            if self.recv_calls%5==0:return WANT_READ
            try:chunk=self.socket.recv(min(size,max_io))
            except BlockingIOError:return WANT_READ
            except OSError:return TRANSPORT
            C.memmove(data,chunk,len(chunk));received[0]=len(chunk);return OK
        self.send,self.receive=IO(send),IO(receive)
        self.transport=Transport(self.send,self.receive,None)
    def finish(self):
        self.socket.close();self.thread.join(3)
        if self.thread.is_alive():raise AssertionError('OpenSSL peer did not terminate')

class TLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory();cls.root=Path(cls.directory.name)
        def command(*args):subprocess.run(['openssl',*args],cwd=cls.root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        command('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','ca.key','-out','ca.pem','-days','10','-subj','/CN=TLS Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        command('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=tls.test')
        (cls.root/'extensions').write_text('subjectAltName=DNS:tls.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
        command('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','2','-extfile','extensions')
        command('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','other.key','-out','other.pem','-days','10','-subj','/CN=Unrelated Test CA')
        command('req','-new','-newkey','rsa:2048','-nodes','-keyout','rsa.key','-out','rsa.csr','-subj','/CN=tls.test')
        command('x509','-req','-in','rsa.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','rsa.pem','-days','2','-extfile','extensions')
        cls.ca=(cls.root/'ca.pem').read_bytes()
        cls.contexts={}
        cls.rsa_contexts={}
        cls.sni=[]
        for version in [ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3]:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version=context.maximum_version=version
            context.load_cert_chain(cls.root/'server.pem',cls.root/'server.key')
            context.set_servername_callback(lambda sock,name,ctx:cls.sni.append(name))
            cls.contexts[version]=context
            rsa=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            rsa.minimum_version=rsa.maximum_version=version
            rsa.load_cert_chain(cls.root/'rsa.pem',cls.root/'rsa.key')
            cls.rsa_contexts[version]=rsa
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup();assert lib.dmod_deinit()==0
    def setUp(self):
        self.connections=[];self.configs=[];self.peers=[];self.fail_entropy=False
        lib.test_utc_available(1);lib.test_utc_offset(0)
        def entropy(user,out,n):
            if self.fail_entropy:return -1
            C.memmove(out,os.urandom(n),n);return 0
        self.entropy=Entropy(entropy)
        self.platform=Platform(self.entropy,None,1024*1024,4)
        self.assertEqual(lib.dmtls_initialize(C.byref(self.platform)),OK)
    def tearDown(self):
        for c in self.connections:self.assertEqual(lib.dmtls_connection_destroy(c),OK)
        for c in self.configs:self.assertEqual(lib.dmtls_config_destroy(c),OK)
        for p in self.peers:p.finish()
        self.assertEqual(lib.dmtls_shutdown(),OK)
        self.assertEqual(lib.test_live_allocations(),0,'TLS heap leak')
    def config(self,ca=None):
        data=self.ca if ca is None else ca;out=C.c_void_p()
        self.assertEqual(lib.dmtls_config_create(data,len(data),C.byref(out)),OK)
        self.configs.append(out);return out
    def connection(self,version=ssl.TLSVersion.TLSv1_3,host=b'tls.test',config=None,abrupt=False):
        peer=Peer(self.contexts[version],abrupt=abrupt);self.peers.append(peer)
        out=C.c_void_p()
        self.assertEqual(lib.dmtls_connection_create(config or self.config(),host,C.byref(peer.transport),10000,10000,C.byref(out)),OK)
        self.connections.append(out);return out,peer
    def drive(self,fn,*args):
        deadline=time.monotonic()+12
        while True:
            rc=fn(*args)
            if rc not in (WANT_READ,WANT_WRITE):return rc
            if time.monotonic()>deadline:self.fail('TLS operation failed to make progress')
            time.sleep(.0001)
    def status(self,c):
        out=Status();self.assertEqual(lib.dmtls_status(c,C.byref(out)),OK);return out
    def exchange(self,version,abrupt=False):
        c,peer=self.connection(version,abrupt=abrupt)
        self.assertEqual(self.drive(lib.dmtls_handshake,c),OK)
        self.assertIn('tls.test',self.sni)
        message=b'hello over authenticated TLS';buffer=C.create_string_buffer(message);sent=C.c_size_t()
        self.assertEqual(self.drive(lib.dmtls_write,c,buffer,len(message),C.byref(sent)),OK)
        self.assertEqual(sent.value,len(message))
        received=bytearray()
        while len(received)<len(message):
            out=C.create_string_buffer(8);n=C.c_size_t()
            self.assertEqual(self.drive(lib.dmtls_read,c,out,len(out),C.byref(n)),OK)
            received.extend(out.raw[:n.value])
        self.assertEqual(received,message)
        out=C.create_string_buffer(8);n=C.c_size_t(99)
        self.assertEqual(self.drive(lib.dmtls_read,c,out,len(out),C.byref(n)),TRUNCATED if abrupt else PEER_CLOSED)
        self.assertEqual(n.value,0)
        if not abrupt:self.assertEqual(self.drive(lib.dmtls_close,c),OK)
        self.assertGreater(peer.send_calls,5);self.assertGreater(peer.recv_calls,5)
    def test_tls12_interoperability(self):self.exchange(ssl.TLSVersion.TLSv1_2)
    def test_tls13_interoperability(self):self.exchange(ssl.TLSVersion.TLSv1_3)
    def test_unannounced_tcp_eof_is_truncation(self):self.exchange(ssl.TLSVersion.TLSv1_3,True)
    def test_hostname_required_and_verified(self):
        c,_=self.connection(host=b'wrong.test')
        self.assertEqual(self.drive(lib.dmtls_handshake,c),CERT)
        self.assertTrue(self.status(c).verification_flags&2)
    def test_future_certificate_rejected(self):
        lib.test_utc_offset(-86400*30);c,_=self.connection()
        self.assertEqual(self.drive(lib.dmtls_handshake,c),CERT)
        self.assertTrue(self.status(c).verification_flags&8)
    def test_expired_certificate_rejected(self):
        lib.test_utc_offset(86400*4);c,_=self.connection()
        self.assertEqual(self.drive(lib.dmtls_handshake,c),CERT)
        self.assertTrue(self.status(c).verification_flags&4)
    def test_missing_utc_fails_before_transport(self):
        c,peer=self.connection();lib.test_utc_available(0)
        self.assertEqual(lib.dmtls_handshake(c),UTC);self.assertEqual(peer.send_calls,0)
        self.assertEqual(lib.dmtls_handshake(c),UTC)
    def test_deadlines_and_shared_config_lifetime(self):
        config=self.config();c,_=self.connection(config=config)
        self.assertEqual(lib.dmtls_config_destroy(config),BUSY)
        self.assertEqual(lib.dmtls_shutdown(),BUSY)
        lib.test_ticks_advance(10000)
        self.assertEqual(lib.dmtls_handshake(c),TIMEOUT)
    def test_callback_reentry_is_rejected(self):
        c,p=self.connection()
        observed=[]
        def reenter():observed.append(lib.dmtls_status(c,C.byref(Status())))
        p.reentrant=reenter
        self.assertEqual(self.drive(lib.dmtls_handshake,c),OK)
        self.assertTrue(observed)
        self.assertEqual(set(observed),{BUSY})
    def test_partial_or_malformed_ca_bundle_rejected(self):
        for data in [b'invalid',self.ca+b'-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n']:
            out=C.c_void_p(1);self.assertEqual(lib.dmtls_config_create(data,len(data),C.byref(out)),CERT);self.assertIsNone(out.value)
    def test_entropy_failure_during_initialization_has_no_fallback(self):
        self.assertEqual(lib.dmtls_shutdown(),OK);self.fail_entropy=True
        self.assertEqual(lib.dmtls_initialize(C.byref(self.platform)),ENTROPY)
        self.assertEqual(lib.test_live_allocations(),0)
        self.fail_entropy=False;self.assertEqual(lib.dmtls_initialize(C.byref(self.platform)),OK)
    def test_connection_limit_and_invalid_handles(self):
        config=self.config()
        for _ in range(4):self.connection(config=config)
        p=self.peers[0];out=C.c_void_p(1)
        self.assertEqual(lib.dmtls_connection_create(config,b'tls.test',C.byref(p.transport),1000,1000,C.byref(out)),LIMIT)
        self.assertIsNone(out.value)
        self.assertEqual(lib.dmtls_connection_destroy(C.c_void_p(1)),ARGUMENT)
        self.assertEqual(lib.dmtls_config_destroy(C.c_void_p(1)),ARGUMENT)
    def test_rsa_certificate_tls12_and_tls13(self):
        for version,context in self.rsa_contexts.items():
            old=self.contexts[version];self.contexts[version]=context
            try:
                c,_=self.connection(version)
                self.assertEqual(self.drive(lib.dmtls_handshake,c),OK)
            finally:self.contexts[version]=old
    def test_untrusted_ca_rejected(self):
        config=self.config((self.root/'other.pem').read_bytes());c,_=self.connection(config=config)
        self.assertEqual(self.drive(lib.dmtls_handshake,c),CERT)
        self.assertTrue(self.status(c).verification_flags&1)
    def test_write_retry_requires_the_same_buffer(self):
        c,p=self.connection();self.assertEqual(self.drive(lib.dmtls_handshake,c),OK)
        p.force_send=lambda data,size,sent:WANT_WRITE
        data=C.create_string_buffer(b'payload');other=C.create_string_buffer(b'payload');n=C.c_size_t()
        self.assertEqual(lib.dmtls_write(c,data,7,C.byref(n)),WANT_WRITE)
        self.assertEqual(lib.dmtls_write(c,other,7,C.byref(n)),ARGUMENT)
        self.assertEqual(n.value,0)
        self.assertEqual(lib.dmtls_read(c,other,7,C.byref(n)),BUSY)
    def test_invalid_transport_count_fails_connection(self):
        c,p=self.connection()
        def bad_send(data,size,sent):sent[0]=size+1;return OK
        p.force_send=bad_send
        self.assertEqual(lib.dmtls_handshake(c),TRANSPORT)
        self.assertEqual(lib.dmtls_handshake(c),TRANSPORT)
    def test_read_deadline_survives_want_retries(self):
        c,_=self.connection();self.assertEqual(self.drive(lib.dmtls_handshake,c),OK)
        data=C.create_string_buffer(100);n=C.c_size_t(99)
        self.assertIn(lib.dmtls_read(c,data,100,C.byref(n)),(WANT_READ,WANT_WRITE))
        lib.test_ticks_advance(10000)
        self.assertEqual(lib.dmtls_read(c,data,100,C.byref(n)),TIMEOUT)
        self.assertEqual(n.value,0)
    def test_heap_budget(self):
        self.assertEqual(lib.dmtls_shutdown(),OK)
        self.platform.heap_limit=32768;self.assertEqual(lib.dmtls_initialize(C.byref(self.platform)),OK)
        config=self.config();p=Peer(self.contexts[ssl.TLSVersion.TLSv1_3]);self.peers.append(p);out=C.c_void_p()
        rc=lib.dmtls_connection_create(config,b'tls.test',C.byref(p.transport),1000,1000,C.byref(out))
        if rc==OK:
            self.connections.append(out);rc=self.drive(lib.dmtls_handshake,out)
        self.assertLess(rc,0)

if __name__=='__main__':unittest.main(verbosity=2)
