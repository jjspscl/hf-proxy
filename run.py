#!/usr/bin/env python3
import argparse
import base64
import hmac
import json
import logging
import os
import select
import socket
import socketserver
import time

logger = logging.getLogger("hf-proxy")

DEFAULT_ALLOWED_SUFFIXES = (
    ".huggingface.co",
    ".hf.co",
    ".xethub.hf.co",
)
HEALTH_UPSTREAM = ("huggingface.co", 443)
HEADER_TIMEOUT = 30


def normalize_suffix(value):
    value = value.strip().lower()
    if not value:
        raise ValueError("empty host suffix")
    return value if value.startswith(".") else "." + value


def host_allowed(host, suffixes):
    host = host.lower()
    return any(host == s[1:] or host.endswith(s) for s in suffixes)


class BadRequest(Exception):
    pass


class Proxy(socketserver.StreamRequestHandler):
    timeout = HEADER_TIMEOUT

    def log_message(self, message, *args):
        logger.info(
            "client=%s %s",
            self.client_address[0],
            message % args,
        )

    def respond(self, status, body=b"", content_type="text/plain", extra=()):
        if isinstance(body, str):
            body = body.encode()
        head = [f"HTTP/1.1 {status}"]
        head.extend(extra)
        if body:
            head.append(f"Content-Type: {content_type}")
        head.append(f"Content-Length: {len(body)}")
        head.append("Connection: close")
        self.wfile.write(("\r\n".join(head) + "\r\n\r\n").encode() + body)

    def credentials_valid(self, headers):
        expected = "Basic " + base64.b64encode(
            (self.server.token + ":").encode()
        ).decode()
        supplied = headers.get("proxy-authorization") or headers.get(
            "authorization", ""
        )
        return hmac.compare_digest(supplied.encode(), expected.encode())

    def credentials_supplied(self, headers):
        return bool(
            headers.get("proxy-authorization") or headers.get("authorization")
        )

    def read_request(self):
        line = self.rfile.readline(65537).decode("latin1").strip()
        if not line:
            return None
        parts = line.split()
        if len(parts) != 3:
            raise BadRequest("malformed request line")
        method, target, _version = parts
        headers = {}
        while True:
            raw = self.rfile.readline(65537).decode("latin1")
            if raw in ("\r\n", "\n", ""):
                break
            if ":" not in raw:
                raise BadRequest("malformed header")
            key, value = raw.split(":", 1)
            headers[key.lower()] = value.strip()
        return method, target, headers

    def handle(self):
        try:
            try:
                request = self.read_request()
            except BadRequest as exc:
                self.log_message("rejected bad request: %s", exc)
                self.respond("400 Bad Request", f"bad request: {exc}\n")
                return
            if request is None:
                return
            method, target, headers = request

            if method.upper() == "GET" and target.split("?", 1)[0] == "/healthz":
                self.handle_health(headers)
                return

            authorized = self.credentials_valid(headers)
            self.log_message(
                "request method=%s target=%s authorized=%s",
                method,
                target,
                authorized,
            )

            if not authorized:
                self.log_message("rejected unauthorized request")
                self.respond(
                    "407 Proxy Authentication Required",
                    extra=['Proxy-Authenticate: Basic realm="HF proxy"'],
                )
                return

            if method.upper() != "CONNECT":
                self.log_message("rejected unsupported method=%s", method)
                self.respond("405 Method Not Allowed")
                return

            try:
                host, port = target.rsplit(":", 1)
                port = int(port)
                if not host or not 0 < port < 65536:
                    raise ValueError
            except ValueError:
                self.log_message("rejected bad target=%s", target)
                self.respond("400 Bad Request", "bad CONNECT target, expected host:port\n")
                return

            if not host_allowed(host, self.server.allowed):
                self.log_message("rejected destination host=%s", host)
                self.respond("403 Forbidden", f"host not allowed: {host}\n")
                return

            self.log_message("connecting upstream host=%s port=%d", host, port)
            try:
                upstream = socket.create_connection(
                    (host, port), timeout=self.server.connect_timeout
                )
            except OSError as exc:
                reason = describe_connect_error(exc)
                self.log_message(
                    "upstream connect failed host=%s port=%d reason=%s",
                    host, port, reason,
                )
                self.respond(
                    "502 Bad Gateway",
                    f"cannot reach {host}:{port}: {reason}\n",
                )
                return

            try:
                self.relay(upstream, host, port)
            finally:
                upstream.close()

        except Exception:
            logger.exception("connection error")

    def handle_health(self, headers):
        if not self.credentials_supplied(headers):
            self.respond("200 OK", "ok\n")
            return
        if not self.credentials_valid(headers):
            self.log_message("healthz rejected: bad credentials")
            self.respond("401 Unauthorized", "unauthorized\n")
            return
        host, port = self.server.health_upstream
        started = time.monotonic()
        try:
            sock = socket.create_connection(
                (host, port), timeout=self.server.connect_timeout
            )
            sock.close()
        except OSError as exc:
            body = {
                "auth": True,
                "upstream": "error",
                "error": describe_connect_error(exc),
            }
            self.respond("502 Bad Gateway", json.dumps(body) + "\n", "application/json")
            return
        body = {
            "auth": True,
            "upstream": "ok",
            "latency_ms": int((time.monotonic() - started) * 1000),
        }
        self.respond("200 OK", json.dumps(body) + "\n", "application/json")

    def relay(self, upstream, host, port):
        upstream.settimeout(None)
        self.connection.settimeout(None)
        self.log_message("upstream connected host=%s port=%d", host, port)

        self.wfile.write(
            b"HTTP/1.1 200 Connection Established\r\n"
            b"Proxy-Agent: local-hf-proxy\r\n\r\n"
        )

        sockets = [self.connection, upstream]
        up = down = 0
        started = last_report = time.monotonic()
        reason = "error"
        try:
            while True:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, self.server.idle_timeout
                )
                if exceptional:
                    reason = "socket_exception"
                    break
                if not readable:
                    reason = "idle_timeout"
                    break

                done = False
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        reason = (
                            "client_closed"
                            if sock is self.connection
                            else "upstream_closed"
                        )
                        done = True
                        break
                    if sock is self.connection:
                        upstream.sendall(data)
                        up += len(data)
                    else:
                        self.connection.sendall(data)
                        down += len(data)
                    now = time.monotonic()
                    if now - last_report >= 10:
                        self.log_message(
                            "relay progress host=%s bytes_up=%d bytes_down=%d",
                            host, up, down,
                        )
                        last_report = now
                if done:
                    break
        finally:
            self.log_message(
                "tunnel closed host=%s duration_s=%.1f bytes_up=%d bytes_down=%d reason=%s",
                host, time.monotonic() - started, up, down, reason,
            )


def describe_connect_error(exc):
    if isinstance(exc, socket.gaierror):
        return "dns lookup failed"
    if isinstance(exc, socket.timeout):
        return "connect timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    return f"connect error ({exc})"


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address,
        token,
        allowed=DEFAULT_ALLOWED_SUFFIXES,
        connect_timeout=15.0,
        idle_timeout=300.0,
        health_upstream=HEALTH_UPSTREAM,
    ):
        super().__init__(address, Proxy)
        self.token = token
        self.allowed = tuple(allowed)
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.health_upstream = health_upstream


def env_default(name, default, cast=str):
    value = os.environ.get(name)
    return cast(value) if value else default


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", default=os.environ.get("HF_PROXY_TOKEN"))
    parser.add_argument(
        "--bind", default=env_default("HF_PROXY_BIND", "0.0.0.0"),
        help="interface to listen on (default 0.0.0.0)",
    )
    parser.add_argument(
        "--port", type=int, default=env_default("HF_PROXY_PORT", 8899, int)
    )
    parser.add_argument(
        "--connect-timeout", type=float,
        default=env_default("HF_PROXY_CONNECT_TIMEOUT", 15.0, float),
        help="seconds to wait for the upstream connection (default 15)",
    )
    parser.add_argument(
        "--idle-timeout", type=float,
        default=env_default("HF_PROXY_IDLE_TIMEOUT", 300.0, float),
        help="seconds without traffic before a tunnel is closed (default 300)",
    )
    parser.add_argument(
        "--allow-host", action="append", default=[], metavar="SUFFIX",
        help="extra allowed host (exact or subdomain match); repeatable. "
             "Also HF_PROXY_ALLOW_HOSTS (comma-separated)",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    args = parser.parse_args(argv)
    if not args.token:
        parser.error("token required: set HF_PROXY_TOKEN or pass --token")
    extra = list(args.allow_host)
    extra += [h for h in os.environ.get("HF_PROXY_ALLOW_HOSTS", "").split(",") if h.strip()]
    try:
        args.allowed = DEFAULT_ALLOWED_SUFFIXES + tuple(
            normalize_suffix(h) for h in extra
        )
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    server = Server(
        (args.bind, args.port),
        args.token,
        allowed=args.allowed,
        connect_timeout=args.connect_timeout,
        idle_timeout=args.idle_timeout,
    )
    logger.info("listening on %s:%d", args.bind, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
