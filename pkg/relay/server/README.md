# Relay Server

The Relay Server is a core component of the OpenEBL system that provides a network communication layer for exchanging and broadcasting messages between different components such as Certificate Authority servers, Business Unit servers, and other relay servers. It implements a publish-subscribe messaging pattern using the Nostr protocol for secure and reliable message distribution.

## Architecture

The Relay Server acts as a message broker that enables:

- **Event Publishing**: Components can publish events to the relay network
- **Event Subscription**: Components can subscribe to receive events from specific offsets
- **Peer-to-Peer Communication**: Multiple relay servers can form a distributed network
- **Message Persistence**: Events are stored in a PostgreSQL database for reliability
- **Mutual TLS (mTLS)**: Secure communication between relay servers using certificate-based authentication

## Configuration

The relay server is configured using a YAML configuration file with the following structure:

```yaml
# Database configuration for event storage
database:
  host: "127.0.0.1"
  port: 5432
  user: "root"
  password: ""
  database: "relay_db"
  pool: 5
  sslmode: "disable"

# Local address to bind the server
local_address: ":9001"

# List of other relay server peers to connect to
other_peers: []

# OpenTelemetry endpoint for observability
otlp_endpoint: ""

# Mutual TLS configuration
mtls:
  cert: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  cert_private_key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  cert_server: "https://ca-server:8443"
```

### Configuration Parameters

- **database**: PostgreSQL database configuration for event persistence
- **local_address**: Address and port to bind the relay server (default: ":9001")
- **other_peers**: Array of other relay server addresses to connect to for network formation
- **otlp_endpoint**: OpenTelemetry endpoint for metrics and tracing
- **mtls**: Mutual TLS configuration for secure peer-to-peer communication
  - **cert**: PEM-encoded TLS certificate
  - **cert_private_key**: PEM-encoded private key for the certificate
  - **cert_server**: Certificate Authority server endpoint for retrieving root certificates.

## Usage

### Command Line Interface

The relay server provides a CLI with the following commands:

```bash
# Run the relay server
./relay-server server -c config.yaml

# Migrate the database
./relay-server migrate -p migrations -c config.yaml
```

#### Available Commands

- **server**: Run the relay server with the specified configuration
- **migrate**: Run database migrations to set up the required schema

#### Command Options

- `-c, --config`: Path to the configuration file (default: "config.yaml")
- `-p, --path`: Path to the migration files (default: "migrations", for migrate command)
