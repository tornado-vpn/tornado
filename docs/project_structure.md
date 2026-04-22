# Project Structure

This map describes repository ownership and runtime relevance.

```text
D:\tornado-vpn
|-- assets/
|   |-- icon.ico
|   |-- icons/
|   `-- images/
|-- client/
|   |-- linux/
|   |   |-- src/main.py
|   |   |-- DEBIAN/
|   |   `-- requirements.txt
|   `-- windows/
|       |-- src/main.py
|       |-- setup.iss
|       |-- TornadoVPN-client.spec
|       `-- requirements.txt
|-- docs/
|   |-- index.md
|   |-- architecture.md
|   |-- setup.md
|   |-- security.md
|   |-- operations.md
|   |-- api_reference.md
|   |-- code_walkthrough.md
|   |-- project_structure.md
|   |-- build_linux.md
|   `-- build_windows.md
|-- server/
|   |-- setup.sh
|   |-- schema.sql
|   |-- requirements.txt
|   |-- pyproject.toml
|   |-- microservices/
|   |   |-- MASTER_service.py
|   |   |-- auth_service.py
|   |   |-- session_service.py
|   |   |-- wg_manager.py
|   |   |-- tor_manager.py
|   |   |-- ipam_service.py
|   |   |-- user_service.py
|   |   |-- key_rotator.py
|   |   |-- bootstrap_keys.py
|   |   |-- log_manage.py
|   |   |-- os_service.py
|   |   |-- api_service.py
|   |   |-- services.json
|   |   `-- *_config.json
|   |-- tornadoutils/
|   |   |-- security_utils/
|   |   |-- metrics_service/
|   |   |-- logging_utils/
|   |   |-- admin_service_handler_utils/
|   |   `-- client_service_handler_utils/
|   `-- web-interfaces/
|       |-- admin-dashboard/
|       |   |-- main.py
|       |   |-- schemas.py
|       |   `-- static/
|       `-- client-connect/
|           |-- main.py
|           `-- schemas.py
|-- mkdocs.yml
|-- ATTRIBUTIONS.md
`-- LICENSE
```

## Ownership by Layer

- `client/*`: desktop clients and platform-specific packaging.
- `server/microservices/*`: backend process mesh and service sockets.
- `server/web-interfaces/*`: public/admin HTTP APIs and web assets.
- `server/tornadoutils/*`: shared handlers, auth utilities, logging, metrics.
- `server/schema.sql`: authoritative PostgreSQL schema baseline.
- `docs/*`: source-of-truth documentation consumed by MkDocs.

## Runtime-Critical Files

- `server/setup.sh`: host bootstrap, package install, service provisioning, NGINX and systemd setup.
- `server/microservices/services.json`: child process definitions for `MASTER_service.py`.
- `server/microservices/api_services.json`: supervised FastAPI process definitions.
- `server/microservices/*_config.json`: socket paths, TTL values, interface config, and service-specific policies.
- `server/web-interfaces/client-connect/main.py`: client auth and connection negotiation API.
- `server/web-interfaces/admin-dashboard/main.py`: admin control plane API and dashboard integration.

## Generated Output

- `site/`: generated static documentation output from MkDocs; not source documentation.
