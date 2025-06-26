# Business Unit Server

Business Unit Server is a comprehensive service that provides business unit management and trade document management features. All the business logic of trade documents is implemented in the service.

## ER Model

![alt text](<BU Server ER Model.svg>)

### Components and Definitions

- **User**

  Administrator of Business Unit with access to the management interface. Users can manage business units, applications, and API keys through the web-based management portal. Users have authentication and authorization capabilities with password management features.

- **Application**

  External applications (e.g., OpenEBL Portal) that integrate with the Business Unit Server to access trade document services. Applications are authenticated via API keys and can perform operations on behalf of business units. Each application can have multiple API keys for different environments or purposes.

- **Business Unit**

  A legal entity that can issue, manage, and process trade documents. Business units represent organizations such as banks, shipping companies, or trading firms that participate in international trade. Each business unit has its own authentication mechanisms and can manage multiple trade documents.

- **Business Unit Authentication**

  Certificate-based authentication system for business units, enabling secure communication and document signing. This includes X.509 certificates and associated private keys for cryptographic operations and identity verification.

- **Trade Document**

  Electronic trade documents (primarily Electronic Bills of Lading - EBL) issued and managed by business units. These documents support the full lifecycle of trade operations including issuance, transfer, amendment, surrender, and completion.

## Architecture

The Business Unit Server consists of three main components:

### 1. API Server

- **RESTful API** for trade document management and business unit operations
- **Authentication** via API keys for application access
- **EBL Lifecycle Management** including create, update, transfer, return, amend, surrender, and accomplish operations
- **Business Unit Management** for creating and managing business entities
- **Document Storage** with PostgreSQL backend
- **Health Check** endpoint for monitoring

### 2. Management Server

- **Web-based Management Interface** for administrators
- **User Management** including creation, updates, password management, and status control
- **Application Management** for registering and configuring external applications
- **API Key Management** for authentication and access control
- **Single Page Application (SPA)** frontend for user interactions

### 3. Broker Service

- **Message Relay** with external relay servers for inter-organizational communication
- **Certificate-based Communication** using X.509 certificates for secure messaging
- **Batch Processing** with configurable intervals and batch sizes
- **Background Processing** for asynchronous operations

## Key Features

### Trade Document Management

- **Electronic Bill of Lading (EBL)** creation and management
- **Document Transfer** between business units
- **Amendment Requests** and processing
- **Document Surrender** and accomplishment
- **Document History** and audit trail
- **File-based Document Storage** with metadata

### Security and Authentication

- **Multi-level Authentication**: User tokens, API keys, and business unit certificates
- **Certificate Management** for business unit authentication
- **Secure Communication** with TLS and certificate validation
- **API Key Rotation** and revocation capabilities

### Integration and Notifications

- **Webhook System** for real-time event notifications
- **Configurable Endpoints** with retry mechanisms
- **Event Types**: Document state changes, business unit updates, and system events
- **Delivery Guarantees** with configurable retry policies

### Monitoring and Operations

- **Health Check** endpoints for system monitoring
- **Logging and Tracing** with OpenTelemetry integration
- **Database Migrations** for schema management
- **Configuration Management** via YAML files

## API Endpoints

[API Endpoint](api/api.yaml)

[Manager API Endpoint](manager/manager_api.yaml)

### Business Unit Management

- `POST /business_unit` - Create a new business unit
- `GET /business_unit` - List all business units
- `GET /business_unit/{id}` - Get business unit details
- `POST /business_unit/{id}` - Update business unit
- `POST /business_unit/{id}/status` - Update business unit status
- `POST /business_unit/{id}/authentication` - Create authentication certificate
- `GET /business_unit/{id}/authentication` - List authentication certificates
- `DELETE /business_unit/{id}/authentication/{auth_id}` - Revoke certificate

### Electronic Bill of Lading (EBL)

- `POST /ebl` - Create/Issue a new EBL
- `GET /ebl` - List EBLs with filtering and pagination
- `GET /ebl/{id}` - Get EBL details
- `POST /ebl/{id}/update` - Update EBL content
- `POST /ebl/{id}/transfer` - Transfer EBL to another party
- `POST /ebl/{id}/return` - Return EBL to previous holder
- `POST /ebl/{id}/amendment_request` - Request EBL amendment
- `POST /ebl/{id}/amend` - Amend EBL content
- `POST /ebl/{id}/surrender` - Surrender EBL for goods release
- `POST /ebl/{id}/print` - Print EBL to paper
- `POST /ebl/{id}/accomplish` - Mark EBL as accomplished
- `DELETE /ebl/{id}` - Delete EBL
- `GET /ebl/{id}/document` - Download EBL document file

### Webhook Management

- `POST /webhook` - Create webhook endpoint
- `GET /webhook` - List webhook endpoints
- `GET /webhook/{id}` - Get webhook details
- `POST /webhook/{id}` - Update webhook configuration
- `DELETE /webhook/{id}` - Delete webhook endpoint

### Management Interface

- `GET /api/login` - User authentication
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{id}` - Get user details
- `POST /api/users/{id}` - Update user
- `POST /api/users/{id}/status` - Update user status
- `POST /api/users/{id}/change_password` - Change user password
- `POST /api/users/{id}/reset_password` - Reset user password
- `GET /api/applications` - List applications
- `POST /api/applications` - Create application
- `GET /api/applications/{id}` - Get application details
- `POST /api/applications/{id}` - Update application
- `POST /api/applications/{id}/status` - Update application status
- `POST /api/applications/{id}/api_keys` - Create API key
- `GET /api/applications/{id}/api_keys` - List API keys
- `DELETE /api/applications/{id}/api_keys/{key_id}` - Revoke API key

## Command Line Interface

The server provides three main commands:

- `server` - Run the main API server
- `manager` - Run the management interface server
- `broker` - Run the message broker service
- `migrate` - Run database migrations

Configuration is managed through YAML files with support for database settings, server addresses, broker configuration, webhook settings, and OpenTelemetry tracing.

## Initialize

When deploying the Business Unit Server for the first time, follow these initialization steps:

### 1. Prerequisites

- **PostgreSQL Database**: Ensure PostgreSQL is installed and running
- **Configuration File**: Create a `config.yaml` file based on the template
- **Environment Variables**: Set required environment variables for database connection
- **TLS Certificates**: Prepare certificates for broker communication (if using broker service)

### 2. Database Setup

#### Configure Database Connection

Edit the `config.yaml` file with your database settings:

```yaml
database:
  host: "your-postgres-host"
  port: 5432
  user: "your-db-user"
  password: "your-db-password"
  database: "your-database-name"
  pool: 5
  sslmode: "disable" # or "require" for production
```

#### Run Database Migration

Execute the migration command to create all required database tables and initial data:

```bash
./bu-server migrate -c config.yaml -p migrations
```

This command will:

- Create the database if it doesn't exist
- Create all required tables (`user`, `application`, `api_key`, `business_unit`, etc.)
- Insert a default root user for initial access

### 3. Default Credentials

After successful migration, a default administrator account is created:

- **Username**: `root`
- **Password**: `root`
- **User ID**: `usr_00000000-0000-0000-0000-000000000000`

**⚠️ SECURITY WARNING**: Change the default password immediately after first login!

### 4. Server Configuration

#### API Server Configuration

```yaml
server:
  host: "" # Leave empty to bind to all interfaces
  port: 8080 # API server port
```

#### Management Server Configuration

```yaml
manager:
  host: "" # Leave empty to bind to all interfaces
  port: 8081 # Management interface port
```

#### Broker Configuration

```yaml
broker:
  relay_server: "ws://relay-server:9001"
  cert: |
    -----BEGIN CERTIFICATE-----
    [Your certificate content]
    -----END CERTIFICATE-----
  cert_private_key: |
    -----BEGIN PRIVATE KEY-----
    [Your private key content]
    -----END PRIVATE KEY-----
  cert_server: "http://cert-server:9101"
  check_interval: 30
  batch_size: 10
```

#### Webhook Configuration

```yaml
webhook:
  check_interval: 10 # seconds
  batch_size: 10
  timeout: 5 # seconds
  max_retry: 5
```

### 5. Start Services

#### Start API Server

```bash
./bu-server server -c config.yaml
```

#### Start Management Interface

```bash
./bu-server manager -c config.yaml
```

#### Start Broker

```bash
./bu-server broker -c config.yaml
```

### 6. Initial Setup Tasks

#### Access Management Interface

1. Open your browser to `http://localhost:8081` (or your configured manager port)
2. Login with default credentials:
   - Username: `root`
   - Password: `root`

#### Change Default Password

1. Navigate to Users section
2. Select the root user
3. Use "Change Password" to set a secure password

#### Create First Application

1. Go to Applications section
2. Click "Create Application"
3. Fill in application details:
   - **Name**: Your application name
   - **Company Name**: Your organization name
   - **Status**: Active

#### Generate API Keys

1. Select your newly created application
2. Go to "API Keys" section
3. Click "Create API Key"
4. Copy and securely store the generated API key
