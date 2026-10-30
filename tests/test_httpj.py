#!/usr/bin/env python3
"""HTTPJ regression tests; Python stdlib only (test tooling, not runtime dependencies)."""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'http.java'

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def send_bytes(self, status, data, content_type='text/plain', extra=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        if extra:
            for key, value in extra.items(): self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path == '/redirect':
            self.send_bytes(302, b'', extra={'Location': '/get'})
        elif self.path == '/get':
            self.send_bytes(200, b'{"name":"httpj","arr":[1,2],"nested":{"ok":true}}', 'application/json')
        elif self.path == '/invalid-json':
            self.send_bytes(200, b'{bad json}', 'application/json')
        elif self.path == '/binary':
            self.send_bytes(200, b'\x00\xff\x10\xf0', 'application/octet-stream')
        elif self.path == '/headers':
            self.send_bytes(200, json.dumps({'x-first': self.headers.get('X-First'), 'x-second': self.headers.get('X-Second')}).encode(), 'application/json')
        elif self.path == '/status/404':
            self.send_bytes(404, b'Not Found')
        elif self.path == '/json-plain':
            self.send_bytes(200, b'{"a":1}', 'text/plain')
        elif self.path == '/slow':
            time.sleep(2)
            try: self.send_bytes(200, b'OK')
            except BrokenPipeError: pass
        elif self.path == '/empty':
            self.send_bytes(200, b'')
        else:
            self.send_bytes(200, b'OK')
    def do_POST(self): self.echo()
    def do_PUT(self): self.echo()
    def do_PATCH(self): self.echo()
    def do_DELETE(self): self.echo()
    def echo(self):
        length = int(self.headers.get('Content-Length', '0'))
        payload = self.rfile.read(length)
        self.send_bytes(200, json.dumps({'method': self.command, 'body': payload.decode('utf8'), 'content_type': self.headers.get('Content-Type')}).encode(), 'application/json')

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, capture_output=True, check=True)

class HttpjTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='httpj-tests-')
        d = Path(cls.tmp.name)
        cls.temp = d
        cls.classes = d/'classes'
        cls.classes.mkdir()
        subprocess.run(['javac', '-d', str(cls.classes), str(SOURCE)], check=True, capture_output=True)
        cls.http = Server(('127.0.0.1', 0), Handler)
        cls.http_thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.http_thread.start()
        cls.base = f'http://localhost:{cls.http.server_port}'
        # Local CA and certificates, all generated offline.
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=httpj-test-ca', '-days', '1', cwd=d)
        openssl('req', '-newkey', 'rsa:2048', '-noenc', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost', cwd=d)
        (d/'server.ext').write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext', cwd=d)
        openssl('req', '-newkey', 'rsa:2048', '-noenc', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=httpj-client', cwd=d)
        (d/'client.ext').write_text('extendedKeyUsage=clientAuth\n')
        openssl('x509', '-req', '-in', 'client.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'client.pem', '-days', '1', '-extfile', 'client.ext', cwd=d)
        # server TLS, no client cert required
        cls.https = Server(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(d/'server.pem', d/'server.key')
        cls.https.socket = ctx.wrap_socket(cls.https.socket, server_side=True)
        threading.Thread(target=cls.https.serve_forever, daemon=True).start()
        cls.tlsbase = f'https://localhost:{cls.https.server_port}'
        cls.badhostbase = f'https://127.0.0.1:{cls.https.server_port}'
        # mTLS server; rejects requests without client cert.
        cls.mtls = Server(('127.0.0.1', 0), Handler)
        mtls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        mtls_ctx.load_cert_chain(d/'server.pem', d/'server.key')
        mtls_ctx.load_verify_locations(d/'ca.pem')
        mtls_ctx.verify_mode = ssl.CERT_REQUIRED
        cls.mtls.socket = mtls_ctx.wrap_socket(cls.mtls.socket, server_side=True)
        threading.Thread(target=cls.mtls.serve_forever, daemon=True).start()
        cls.mtlsbase = f'https://localhost:{cls.mtls.server_port}'
        (d/'body.json').write_text('{"file":true}')

    @classmethod
    def tearDownClass(cls):
        for server in (cls.http, cls.https, cls.mtls): server.shutdown(); server.server_close()
        cls.tmp.cleanup()

    def call(self, *args, source=False):
        cmd = ['java', str(SOURCE)] if source else ['java', '-cp', str(self.classes), 'http']
        return subprocess.run([*cmd, *map(str, args)], capture_output=True, timeout=20)

    def assertSuccess(self, res):
        self.assertEqual(res.returncode, 0, res.stderr.decode(errors='replace'))
        return res.stdout

    def test_01_help(self):
        self.assertIn(b'Usage:', self.assertSuccess(self.call('--help', source=True)))
    def test_02_source_execution_get(self):
        self.assertIn(b'"name": "httpj"', self.assertSuccess(self.call('GET', self.base+'/get', source=True)))
    def test_03_get_pretty(self):
        self.assertIn(b'\n  "arr": [\n', self.assertSuccess(self.call('GET', self.base+'/get')))
    def test_04_raw_json(self):
        self.assertEqual(self.assertSuccess(self.call('GET', self.base+'/get', '--raw')), b'{"name":"httpj","arr":[1,2],"nested":{"ok":true}}')
    def test_05_headers(self):
        out = self.assertSuccess(self.call('GET', self.base+'/headers', '-H', 'X-First: abc', '-H', 'X-Second: xyz'))
        self.assertEqual(json.loads(out)['x-second'], 'xyz')
    def test_06_inline_post(self):
        out = self.assertSuccess(self.call('POST', self.base+'/echo', '-d', '{"msg":"ok"}', '-H', 'Content-Type: application/json'))
        self.assertEqual(json.loads(out)['body'], '{"msg":"ok"}')
    def test_07_file_post(self):
        out = self.assertSuccess(self.call('POST', self.base+'/echo', '-f', self.temp/'body.json'))
        self.assertEqual(json.loads(out)['body'], '{"file":true}')
    def test_08_put(self):
        self.assertEqual(json.loads(self.assertSuccess(self.call('PUT', self.base+'/echo', '-d', 'x')))['method'], 'PUT')
    def test_09_patch(self):
        self.assertEqual(json.loads(self.assertSuccess(self.call('PATCH', self.base+'/echo', '-d', 'x')))['method'], 'PATCH')
    def test_10_delete(self):
        self.assertEqual(json.loads(self.assertSuccess(self.call('DELETE', self.base+'/echo')))['method'], 'DELETE')
    def test_11_response_headers(self):
        out = self.assertSuccess(self.call('GET', self.base+'/get', '-i'))
        self.assertIn(b'content-type: application/json', out.lower())
    def test_12_redirect_default(self):
        self.assertIn(b'HTTP 302', self.call('GET', self.base+'/redirect').stderr)
    def test_13_redirect_follow(self):
        self.assertIn(b'HTTP 200', self.call('GET', self.base+'/redirect', '-L').stderr)
    def test_14_http404_exit(self):
        res = self.call('GET', self.base+'/status/404')
        self.assertEqual(res.returncode, 22)
    def test_15_invalid_args_exit(self):
        res = self.call('GET', self.base+'/get', '--invalid')
        self.assertEqual(res.returncode, 2)
    def test_16_missing_required_option(self):
        self.assertEqual(self.call('GET', self.base+'/get', '-H').returncode, 2)
    def test_17_conflicting_bodies(self):
        self.assertEqual(self.call('POST', self.base+'/echo', '-d', 'a', '-f', self.temp/'body.json').returncode, 2)
    def test_18_bad_cert_pair(self):
        self.assertEqual(self.call('GET', self.base+'/get', '--cert', self.temp/'client.pem').returncode, 2)
    def test_19_invalid_timeout(self):
        self.assertEqual(self.call('GET', self.base+'/get', '--timeout', '0').returncode, 2)
    def test_20_json_plain_detection(self):
        self.assertEqual(self.assertSuccess(self.call('GET', self.base+'/json-plain')), b'{\n  "a": 1\n}\n')
    def test_21_invalid_json_fallback(self):
        self.assertEqual(self.assertSuccess(self.call('GET', self.base+'/invalid-json')), b'{bad json}')
    def test_22_binary_preserved(self):
        self.assertEqual(self.assertSuccess(self.call('GET', self.base+'/binary')), b'\x00\xff\x10\xf0')
    def test_23_empty_body(self):
        self.assertEqual(self.assertSuccess(self.call('GET', self.base+'/empty')), b'')
    def test_24_timeout(self):
        res = self.call('GET', self.base+'/slow', '--timeout', '1')
        self.assertEqual(res.returncode, 1)
    def test_25_https_default_rejects_untrusted(self):
        self.assertEqual(self.call('GET', self.tlsbase+'/get').returncode, 1)
    def test_26_https_trusted_ca(self):
        self.assertIn(b'"name": "httpj"', self.assertSuccess(self.call('GET', self.tlsbase+'/get', '--cacert', self.temp/'ca.pem')))
    def test_27_bad_hostname_rejected(self):
        self.assertEqual(self.call('GET', self.badhostbase+'/get', '--cacert', self.temp/'ca.pem').returncode, 1)
    def test_28_insecure_tls(self):
        self.assertIn(b'"name": "httpj"', self.assertSuccess(self.call('GET', self.tlsbase+'/get', '-k')))
    def test_29_insecure_hostname(self):
        self.assertIn(b'"name": "httpj"', self.assertSuccess(self.call('GET', self.badhostbase+'/get', '-k')))
    def test_30_mtls_requires_client(self):
        self.assertEqual(self.call('GET', self.mtlsbase+'/get', '--cacert', self.temp/'ca.pem').returncode, 1)
    def test_31_mtls_valid_client(self):
        out = self.assertSuccess(self.call('GET', self.mtlsbase+'/get', '--cacert', self.temp/'ca.pem', '--cert', self.temp/'client.pem', '--key', self.temp/'client.key'))
        self.assertIn(b'"name": "httpj"', out)
    def test_32_mtls_k_without_client_fails(self):
        self.assertEqual(self.call('GET', self.mtlsbase+'/get', '-k').returncode, 1)
    def test_33_mtls_insecure_with_client(self):
        out = self.assertSuccess(self.call('GET', self.mtlsbase+'/get', '-k', '--cert', self.temp/'client.pem', '--key', self.temp/'client.key'))
        self.assertIn(b'"name": "httpj"', out)
    def test_34_missing_body_file(self):
        self.assertEqual(self.call('POST', self.base+'/echo', '-f', self.temp/'does-not-exist').returncode, 1)
    def test_35_bad_scheme(self):
        self.assertEqual(self.call('GET', 'file:///etc/passwd').returncode, 2)
    def test_36_missing_ca_file(self):
        self.assertEqual(self.call('GET', self.tlsbase+'/get', '--cacert', self.temp/'missing.pem').returncode, 1)

if __name__ == '__main__':
    unittest.main(verbosity=2)
