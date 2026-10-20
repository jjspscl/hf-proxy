# hf-proxy

Small authenticated HTTP CONNECT proxy that only tunnels to Hugging Face hosts
(`huggingface.co`, `hf.co`, `xethub.hf.co` and their subdomains). No dependencies.

## Run

```sh
HF_PROXY_TOKEN=your-secret python run.py --port 8899
# or: uv run run.py --token your-secret --port 8899
```

Prefer the environment variable: `--token` is visible in the process list.

Options: `--port` (default 8899), `--log-level` (DEBUG/INFO/WARNING/ERROR).

## Client

The token is the Basic auth username, with an empty password:

```sh
export HTTPS_PROXY="http://your-secret:@proxy-host:8899"
```

## Security notes

- Listens on `0.0.0.0`; restrict access with a firewall or bind to a private interface.
- Basic auth is sent unencrypted to the proxy; use a trusted network or tunnel.
- Only `CONNECT` to allowed Hugging Face hosts is permitted.
