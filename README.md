# hf-proxy

Small authenticated HTTP CONNECT proxy that only tunnels to Hugging Face hosts
(`huggingface.co`, `hf.co`, `xethub.hf.co` and their subdomains). No dependencies.

## Run

```sh
HF_PROXY_TOKEN=your-secret python run.py --port 8899
# or: uv run run.py --token your-secret --port 8899
```

Prefer the environment variable: `--token` is visible in the process list.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--token` | `HF_PROXY_TOKEN` | required | Shared secret |
| `--bind` | `HF_PROXY_BIND` | `0.0.0.0` | Interface to listen on |
| `--port` | `HF_PROXY_PORT` | `8899` | Port |
| `--connect-timeout` | `HF_PROXY_CONNECT_TIMEOUT` | `15` | Seconds to wait for the upstream connection |
| `--idle-timeout` | `HF_PROXY_IDLE_TIMEOUT` | `300` | Seconds without traffic before a tunnel closes |
| `--allow-host SUFFIX` (repeatable) | `HF_PROXY_ALLOW_HOSTS` (comma-separated) | none | Extra allowed hosts (exact or subdomain), e.g. `pypi.org`, `pythonhosted.org` |
| `--log-level` | | `INFO` | DEBUG/INFO/WARNING/ERROR |

## Client

The token is the Basic auth username, with an empty password:

```sh
export HTTPS_PROXY="http://your-secret:@proxy-host:8899"
```

Downloading gated models (e.g. pyannote speaker diarization):

```sh
export HTTPS_PROXY="http://$HF_PROXY_TOKEN:@proxy-host:8899" HF_TOKEN=hf_...
python -c 'from pyannote.audio import Pipeline; Pipeline.from_pretrained("pyannote/speaker-diarization-3.1")'
```

## Checking the proxy

`GET /healthz` is answered by the proxy itself:

```sh
# Is the process up? (no auth, no upstream check)
curl -sS --max-time 5 http://proxy-host:8899/healthz

# Is auth right and can the proxy reach Hugging Face?
curl -sS --max-time 10 -u "$TOKEN:" http://proxy-host:8899/healthz
# {"auth": true, "upstream": "ok", "latency_ms": 123}

# End to end through the tunnel
curl -sS --max-time 10 -x "http://$TOKEN:@proxy-host:8899" -I https://huggingface.co
```

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `407` | Wrong or missing token |
| `403` | Host is not on the allowlist (see `--allow-host`) |
| `400` | Malformed request |
| `502` | The proxy cannot reach the upstream host (message says DNS, timeout or refused) |
| Client timeout | Proxy is down, wrong IP/port, or a firewall is in the way |

## Tests

```sh
python -m unittest
```

## Security notes

- Listens on `0.0.0.0` by default; use `--bind` with a private interface address, and/or a firewall.
- Basic auth is sent unencrypted to the proxy; use a trusted network or tunnel.
- Only `CONNECT` to allowed hosts is permitted. Tokens are never logged.
