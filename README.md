# Wonderwall

Wonderwall is a single container that runs three network services together:

- **SNI proxy** (`:443`) — passes through TLS traffic to upstream servers based on hostname, without decrypting it
- **DNS server** (`:53`) — resolves all A-record queries to a single configurable IP
- **Static file server** (`:80`) — serves files over HTTP with optional domain-based routing

Together these services let you stand up a self-contained network environment where all hostnames resolve to your container and TLS traffic is routed transparently to real upstreams.

## How It Works

### SNI Proxy (`:443`)

Reads the TLS ClientHello packet to extract the SNI hostname, then opens a connection to the same hostname on the upstream port and relays bytes in both directions — no decryption, no certificate involved. Connections can be restricted to a hostname allowlist and a specific domain can be reserved for local static content instead of proxying.

### DNS Server (`:53`)

Returns `DNS_A_RECORD_IP` for every A-record query, causing all hostnames to resolve to the container. Other record types receive an empty NOERROR response.

### Static File Server (`:80`)

Serves files from `STATIC_DIR` using Python's built-in HTTP server. `STATIC_DOMAIN` (defaults to the system hostname) controls which host is served over HTTP — requests for any other host are redirected to HTTPS (`301`), and that domain is excluded from TLS proxying so it is handled locally instead.

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `DNS_A_RECORD_IP` | *(required)* | IP address returned for all DNS A-record queries |
| `DNS_PORT` | `53` | DNS listening port |
| `HTTP_PORT` | `80` | Static file server listening port |
| `STATIC_DIR` | `./static` | Directory to serve over HTTP |
| `STATIC_DOMAIN` | *(system hostname)* | Only this domain is served over HTTP; excluded from TLS proxying. Set to empty string to disable filtering and static server. |
| `ALLOWED_HOSTS` | *(allow all)* | Comma-separated regex patterns; only matching SNI hostnames are proxied |
| `UPSTREAM_PORT` | `443` | Port used when connecting to upstream TLS servers |
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

## Running with Docker

```sh
docker build -t wonderwall .
docker run \
  -e DNS_A_RECORD_IP=<your-container-ip> \
  -p 53:53/udp \
  -p 80:80 \
  -p 443:443 \
  wonderwall
```

Static files can be mounted into the container:

```sh
docker run \
  -e DNS_A_RECORD_IP=<your-container-ip> \
  -v /path/to/files:/app/static \
  -p 53:53/udp -p 80:80 -p 443:443 \
  wonderwall
```

## Docker Compose Example

`docker-compose.yml` is an example that places wonderwall on an isolated internal network with a `curl` sidecar configured to use it as its DNS resolver.

```sh
docker compose up
docker compose exec curl curl https://example.com
```

The compose file accepts two variables:

| Variable | Default | Description |
|---|---|---|
| `WONDERWALL_IP` | `172.128.0.128` | IP assigned to the wonderwall container |
| `INTERNAL_SUBNET` | `172.128.0.0/24` | Subnet for the isolated internal network |

## Development

Dependencies are managed with [Poetry](https://python-poetry.org/).

```sh
poetry install
poetry run pytest
```
