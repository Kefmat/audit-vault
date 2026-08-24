# Audit Vault

> A secure, high-performance, and tamper-evident audit logging and vault system designed for modern cloud and enterprise applications.

![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue?style=flat-square&logo=python)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Quick Start](#quick-start)
  - [API Examples](#api-examples)
    - [Logging an Audit Event](#logging-an-audit-event)
    - [Verifying Log Chain Integrity](#verifying-log-chain-integrity)
    - [Retrieving Recent Events](#retrieving-recent-events)
- [Security & Compliance](#security--compliance)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**Audit Vault** provides centralized, immutable event tracking and cryptographic verification for sensitive enterprise actions. Built for compliance, security operations, and system auditing, Audit Vault ensures all recorded events remain verifiable, transparent, and tamper-proof.

---

## Key Features

- **Cryptographic Immutability**: Uses Merkle tree structures and SHA-256 hashing to guarantee log integrity.
- **High Throughput**: Optimized for low-latency ingest and streaming event processing.
- **Role-Based Access Control (RBAC)**: Strict permission boundaries for reading, auditing, and administering logs.
- **Compliance-Ready**: Designed to meet requirements for SOC2, HIPAA, ISO 27001, and GDPR audit trails.
- **Seamless Integrations**: Out-of-the-box connectors for Webhooks, SIEM tools, and Cloud Storage.
- **Queryable Event Log**: Paginated REST API for retrieving and filtering audit events by actor, action, or time range.

---

## Architecture

```mermaid
flowchart TD
    Client[Client Applications] -->|gRPC / REST API| Ingestion[Ingestion Pipeline]
    Ingestion --> Auth[Authentication & RBAC]
    Auth --> Hasher[Cryptographic Hasher]
    Hasher --> Storage[(Immutable Storage Vault)]
    Hasher --> Merkle[Merkle Tree Indexer]
    Merkle --> Auditor[Auditor Verification API]
```

---

## Getting Started

### Prerequisites

- Python `>= 3.10`
- Docker & Docker Compose (for local development)

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Kefmat/audit-vault.git
cd audit-vault
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

For development, install the package in editable mode:

```bash
pip install -e .
```

### Configuration

Create a `.env` file from the provided template:

> The application uses `python-dotenv` to load environment variables automatically at startup.

```bash
cp .env.example .env
```

Configure your vault settings in `.env`:

```env
HOST=0.0.0.0
PORT=8080
LOG_LEVEL=info # options: debug, info, warning, error
VAULT_SECRET_KEY=your-secure-vault-key
STORAGE_DRIVER=memory # options: memory, file
VAULT_FILE_PATH=vault_log.jsonl
API_TOKEN=your-api-token
```

> **Note**: Set `STORAGE_DRIVER=file` and configure `VAULT_FILE_PATH` to persist logs across restarts.

---

## Usage

### Quick Start

Start the local server using Docker Compose:

```bash
docker-compose up -d
```

Or run directly with Python:

```bash
python -m src.main
```

### API Examples

#### Logging an Audit Event

```bash
curl -X POST http://localhost:8080/v1/audit/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -d '{
    "actor": "user_12345",
    "action": "user.password_reset",
    "target": "user_67890",
    "metadata": {
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0"
    }
  }'
```

#### Verifying Log Chain Integrity

```bash
curl -X GET http://localhost:8080/v1/audit/verify \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

#### Retrieving Recent Events

```bash
curl -X GET "http://localhost:8080/v1/audit/events?limit=20&offset=0" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Security & Compliance

If you discover a security vulnerability within Audit Vault, please follow responsible disclosure:

1. **Do not** open a public GitHub issue.
2. Email a report to `security@example.com` with a description, reproduction steps, and potential impact.
3. You will receive an acknowledgement within 48 hours.
4. A patch will be coordinated and released before public disclosure.

---

## Testing

Run the test suite with:

```bash
pytest tests/
```

To include a coverage report:

```bash
pytest tests/ --cov=src
```

---

## Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide before submitting a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes across versions.
