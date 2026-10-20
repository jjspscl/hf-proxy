#!/usr/bin/env python3
import argparse
import base64
import hmac
import logging
import os
import select
import socket
import socketserver
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger("hf-proxy")

ALLOWED_SUFFIXES = (
    ".huggingface.co",
    ".hf.co",
    ".xethub.hf.co",
)

class Proxy(socketserver.StreamRequestHandler):
    def log_message(self, message, *args):
        logger.info(
            "client=%s %s",
            self.client_address[0],
            message % args,
        )

    def authorized(self, headers):
        expected = "Basic " + base64.b64encode(
            (self.server.token + ":").encode()
        ).decode()
        supplied = headers.get("proxy-authorization", "")
        return hmac.compare_digest(supplied, expected)

    def handle(self):
        try:
            line = self.rfile.readline().decode("latin1").strip()
            if not line:
                return

            method, target, version = line.split()
            headers = {}

            while True:
                raw = self.rfile.readline().decode("latin1")
                if raw in ("\r\n", "\n", ""):
                    break
                key, value = raw.split(":", 1)
                headers[key.lower()] = value.strip()

            authorized = self.authorized(headers)
            self.log_message(
                "request method=%s target=%s authorized=%s",
                method,
                target,
                authorized,
            )

            if not authorized:
                self.log_message("rejected unauthorized request")
                self.wfile.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"HF proxy\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                return

            if method.upper() != "CONNECT":
                self.log_message("rejected unsupported method=%s", method)
                self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return

            host, port = target.rsplit(":", 1)
            port = int(port)

            if not any(host == suffix[1:] or host.endswith(suffix)
                       for suffix in ALLOWED_SUFFIXES):
                self.log_message("rejected destination host=%s", host)
                self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return

            self.log_message("connecting upstream host=%s port=%d", host, port)
            upstream = socket.create_connection((host, port), timeout=120)
            upstream.settimeout(None)
            self.connection.settimeout(None)
            self.log_message("upstream connected host=%s port=%d", host, port)

            self.wfile.write(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: local-hf-proxy\r\n\r\n"
            )

            sockets = [self.connection, upstream]
            transferred = {
                self.connection: 0,
                upstream: 0,
            }
            last_report = time.monotonic()
            while True:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, 60
                )
                if exceptional:
                    self.log_message("relay socket exception")
                    break
                if not readable:
                    self.log_message(
                        "relay idle timeout client_to_upstream=%d upstream_to_client=%d",
                        transferred[self.connection],
                        transferred[upstream],
                    )
                    break

                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        self.log_message(
                            "relay closed by %s client_to_upstream=%d upstream_to_client=%d",
                            "client" if sock is self.connection else "upstream",
                            transferred[self.connection],
                            transferred[upstream],
                        )
                        return
                    other = upstream if sock is self.connection else self.connection
                    other.sendall(data)
                    transferred[sock] += len(data)
                    now = time.monotonic()
                    if now - last_report >= 10:
                        self.log_message(
                            "relay progress client_to_upstream=%d upstream_to_client=%d",
                            transferred[self.connection],
                            transferred[upstream],
                        )
                        last_report = now

        except Exception:
            logger.exception("connection error")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

parser = argparse.ArgumentParser()
parser.add_argument("--token", default=os.environ.get("HF_PROXY_TOKEN"))
parser.add_argument("--port", type=int, default=8899)
parser.add_argument(
    "--log-level",
    choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    default="INFO",
)
args = parser.parse_args()
if not args.token:
    parser.error("token required: set HF_PROXY_TOKEN or pass --token")

logging.basicConfig(
    level=getattr(logging, args.log_level),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

server = Server(("0.0.0.0", args.port), Proxy)
server.token = args.token

logger.info("listening on 0.0.0.0:%d", args.port)
server.serve_forever()
