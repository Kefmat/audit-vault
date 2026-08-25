# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-25

### Added
- Cryptographic event hashing with canonical JSON serialization and SHA-256.
- Canonical genesis hash anchor for tamper-evident hash chaining.
- Merkle Tree data structure with cryptographic inclusion proof generation and verification.
- In-memory storage driver (`MemoryVaultStorage`) with concurrency control.
- Append-only file storage driver (`FileVaultStorage`) with JSONL persistence and integrity verification.
- HTTP REST API server with Bearer token authentication and CORS support.
- REST endpoints for event submission, bulk ingestion, querying, pagination, CSV/JSON export, and Merkle proof verification.
- Command-line interface (`src.cli`) for offline log integrity checks.
- Environment configuration loader with validation.
- Comprehensive unit and integration test suite covering all modules.
