import base64
import json
import socket
import threading
import time
import unittest

import run

TOKEN = "secret"
AUTH = "Basic " + base64.b64encode(f"{TOKEN}:".encode()).decode()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class EchoServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.echo, args=(conn,), daemon=True).start()

    def echo(self, conn):
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)

    def close(self):
        self.sock.close()


def start_proxy(**kwargs):
    kwargs.setdefault("allowed", run.DEFAULT_ALLOWED_SUFFIXES + (".localhost", ".127.0.0.1"))
    server = run.Server(("127.0.0.1", 0), TOKEN, **kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def exchange(port, payload, timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(payload)
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("latin1")


def connect_request(target, auth=AUTH):
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if auth:
        lines.append(f"Proxy-Authorization: {auth}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.echo = EchoServer()
        cls.server = start_proxy(connect_timeout=2, idle_timeout=1)
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.echo.close()

    def test_valid_token_tunnels(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(connect_request(f"127.0.0.1:{self.echo.port}"))
            head = b""
            while b"\r\n\r\n" not in head:
                head += s.recv(4096)
            self.assertTrue(head.startswith(b"HTTP/1.1 200 Connection Established"))
            s.sendall(b"ping")
            self.assertEqual(s.recv(4096), b"ping")

    def test_missing_or_wrong_token_is_407(self):
        target = f"127.0.0.1:{self.echo.port}"
        self.assertIn("407", exchange(self.port, connect_request(target, auth=None)).split("\r\n")[0])
        bad = "Basic " + base64.b64encode(b"nope:").decode()
        self.assertIn("407", exchange(self.port, connect_request(target, auth=bad)).split("\r\n")[0])

    def test_disallowed_host_is_403(self):
        for target in ("example.com:443", "evilhuggingface.co:443"):
            first = exchange(self.port, connect_request(target)).split("\r\n")[0]
            self.assertIn("403", first, target)

    def test_unreachable_upstream_is_502_quickly(self):
        started = time.monotonic()
        reply = exchange(self.port, connect_request(f"127.0.0.1:{closed_port()}"))
        self.assertIn("502", reply.split("\r\n")[0])
        self.assertLess(time.monotonic() - started, 4)

    def test_malformed_request_is_400(self):
        self.assertIn("400", exchange(self.port, b"garbage\r\n\r\n").split("\r\n")[0])
        reply = exchange(self.port, connect_request("127.0.0.1:notaport"))
        self.assertIn("400", reply.split("\r\n")[0])

    def test_healthz_without_auth(self):
        reply = exchange(self.port, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn("200 OK", reply.split("\r\n")[0])
        self.assertTrue(reply.endswith("ok\n"))

    def test_healthz_with_auth(self):
        server = start_proxy(health_upstream=("127.0.0.1", self.echo.port))
        try:
            port = server.server_address[1]
            req = f"GET /healthz HTTP/1.1\r\nHost: x\r\nAuthorization: {AUTH}\r\n\r\n"
            reply = exchange(port, req.encode())
            self.assertIn("200 OK", reply.split("\r\n")[0])
            body = json.loads(reply.split("\r\n\r\n", 1)[1])
            self.assertIs(body["auth"], True)
            self.assertEqual(body["upstream"], "ok")
        finally:
            server.shutdown()
            server.server_close()

    def test_healthz_upstream_down_is_502(self):
        server = start_proxy(health_upstream=("127.0.0.1", closed_port()), connect_timeout=2)
        try:
            req = f"GET /healthz HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {AUTH}\r\n\r\n"
            reply = exchange(server.server_address[1], req.encode())
            self.assertIn("502", reply.split("\r\n")[0])
        finally:
            server.shutdown()
            server.server_close()

    def test_idle_tunnel_closes(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(connect_request(f"127.0.0.1:{self.echo.port}"))
            s.recv(4096)
            started = time.monotonic()
            self.assertEqual(s.recv(4096), b"")
            self.assertLess(time.monotonic() - started, 4)


class ConfigTests(unittest.TestCase):
    def test_suffix_matching(self):
        suffixes = run.DEFAULT_ALLOWED_SUFFIXES
        self.assertTrue(run.host_allowed("huggingface.co", suffixes))
        self.assertTrue(run.host_allowed("cdn-lfs.hf.co", suffixes))
        self.assertFalse(run.host_allowed("evilhuggingface.co", suffixes))

    def test_allow_host_and_env(self):
        import os
        os.environ["HF_PROXY_ALLOW_HOSTS"] = "pypi.org, .pythonhosted.org"
        try:
            args = run.parse_args(["--token", "t", "--allow-host", "example.com"])
        finally:
            del os.environ["HF_PROXY_ALLOW_HOSTS"]
        for s in (".example.com", ".pypi.org", ".pythonhosted.org"):
            self.assertIn(s, args.allowed)


if __name__ == "__main__":
    unittest.main()
