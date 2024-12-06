# GFW DNS

A DNS server implementation that supports DNS caching, domain whitelist, and DNS over HTTPS (DoH) proxy for specific domains. It provides features like LRU caching, TTL management, and automatic expired record cleanup.

## Features

- DNS record caching with LRU algorithm (up to 10,000 records)
- Domain whitelist support with TLD (Top Level Domain) matching
- DNS over HTTPS (DoH) proxy for non-whitelisted domains
- SOCKS5 proxy support for DoH queries
- Automatic TTL management and expired record cleanup
- Supports multiple DoH providers with failover
- Concurrent DoH queries for better performance
- SQLite-based in-memory database
- Docker support with easy configuration

## Requirements

- Go 1.21 or higher
- Docker (optional, for containerized deployment)
- SOCKS5 proxy for DoH queries

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/gfwdns.git
cd gfwdns

# Build the binary
go build -o gfwdns

# Run the server
sudo ./gfwdns -config config.yaml
```

### Using Docker

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/yourusername/gfwdns:latest

# Run with default configuration
docker run -d -p 53:53/udp ghcr.io/yourusername/gfwdns:latest

# Run with custom configuration
docker run -d \
  -p 53:53/udp \
  -v /path/to/your/config:/etc/gfwdns \
  ghcr.io/yourusername/gfwdns:latest
```

### Using Docker Compose

```yaml
version: '3'
services:
  gfwdns:
    image: ghcr.io/yourusername/gfwdns:latest
    ports:
      - "53:53/udp"
    volumes:
      - ./config:/etc/gfwdns
    restart: unless-stopped
    privileged: true
```

## Configuration

The server uses a YAML configuration file. Here's an example:

```yaml
server:
  listen: ":53"

upstream:
  # Default DNS server for whitelisted domains
  dns:
    address: "8.8.8.8"
    port: 53
  # DoH servers for non-whitelisted domains
  doh:
    - url: "https://cloudflare-dns.com/dns-query"
      proxy: "127.0.0.1:1080"
      priority: 1
    - url: "https://dns.google/dns-query"
      proxy: "127.0.0.1:1080"
      priority: 2

whitelist:
  file: "/etc/gfwdns/whitelist.txt"
  tld: ["cn", "localhost"]
```

### Whitelist File Format

The whitelist file should contain one domain per line:
```text
example.com
sub.example.com
```

- Supports both exact domain matches and TLD matches
- Domains in the whitelist will be queried through the standard DNS server
- Non-whitelisted domains will be queried through DoH servers using SOCKS5 proxy

## Command Line Arguments

```bash
Usage of gfwdns:
  -config string
        Path to configuration file (default "config.yaml")
```

## DNS Record Types Support

Supports all common DNS record types including:
- A, AAAA Records
- CNAME Records
- MX Records
- TXT Records
- NS Records
- SOA Records
- SRV Records
- CAA Records
- And more...

## Caching Behavior

- Uses LRU (Least Recently Used) algorithm
- Maintains up to 10,000 most frequently accessed records
- Default TTL: 86400 * 30 seconds (30 days)
- Automatic cleanup of expired records

## Security Considerations

- Runs as non-root user in Docker container
- Supports SOCKS5 proxy for secure DoH queries
- Validates DNS responses for integrity
- Uses in-memory SQLite database for record storage

## Known Limitations

- Requires root privileges or CAP_NET_BIND_SERVICE for port 53
- Only supports UDP (no TCP support yet)
- SOCKS5 proxy is required for DoH queries
- In-memory database (data is lost on restart)

## Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/gfwdns.git
cd gfwdns

# Download dependencies
go mod download

# Build
go build -o gfwdns

# Run tests
go test ./...
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Uses [miekg/dns](https://github.com/miekg/dns) for DNS protocol implementation
- Uses [go-sqlite](https://github.com/glebarez/go-sqlite) for SQLite database
- Uses [yaml.v3](https://gopkg.in/yaml.v3) for configuration parsing