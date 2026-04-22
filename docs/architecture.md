# Architecture and Design

## Architectural Principles

Tornado VPN is organized as a local-service mesh on a single host:

- Process supervision and lifecycle control are centralized in `MASTER_service.py`.
- Service-to-service calls use Unix domain sockets in `/run/tornado/*.sock`.
- External API ingress is isolated to two FastAPI apps (`admin-dashboard` and `client-connect`).
- Runtime state is split between Redis (ephemeral/live) and PostgreSQL (durable/history).

## Control Plane vs Data Plane

```mermaid
flowchart TB
  subgraph ControlPlane[Control Plane]
    Master[MASTER_service]
    ApiMgr[api_service]
    OsSvc[os_service]
    UserSvc[user_service]
    AuthSvc[auth_service]
    SessionSvc[session_service]
    Ipam[ipam_service]
    KeyRot[key_rotator]
    BootKeys[bootstrap_keys]
    LogSvc[log_manage]
  end

  subgraph DataPlane[Data Plane]
    WG0[WireGuard wg0\n10.8.0.0/24]
    WG1[WireGuard wg1\n10.9.0.0/24]
    TorMgr[tor_manager]
    TorProc[Tor Process]
    NFT[nftables / iptables]
  end

  subgraph Interfaces[External Interfaces]
    ClientAPI[Client API :4605]
    AdminAPI[Admin API :8000 via NGINX]
    Client[Desktop Clients]
    Admin[Admin Browser]
  end

  Redis[(Redis)]
  PG[(PostgreSQL)]

  Client --> ClientAPI
  Admin --> AdminAPI
  ClientAPI --> AuthSvc
  ClientAPI --> SessionSvc
  ClientAPI --> Ipam
  ClientAPI --> UserSvc
  ClientAPI --> WG0
  ClientAPI --> WG1

  AdminAPI --> ApiMgr
  AdminAPI --> OsSvc
  AdminAPI --> UserSvc
  AdminAPI --> TorMgr
  AdminAPI --> KeyRot
  AdminAPI --> LogSvc

  SessionSvc --> Redis
  Ipam --> Redis
  AuthSvc --> Redis
  AdminAPI --> Redis

  AuthSvc --> PG
  UserSvc --> PG
  SessionSvc --> PG

  WG0 --> NFT
  WG1 --> TorMgr
  TorMgr --> TorProc
```

## Supervisor Model

`MASTER_service.py` loads `services.json`, drops privileges per service user, creates child processes, and performs liveness checks via each service socket `ping` action. On failed heartbeat or crash, restart is scheduled.

```mermaid
sequenceDiagram
  participant Master as MASTER_service
  participant Svc as Child Service
  participant Sock as /run/tornado/*.sock

  Master->>Svc: spawn process
  loop every 10s
    Master->>Sock: {"action":"ping"}
    Sock-->>Master: {"status":"pong"}
  end
  Note over Master,Svc: If process exits or ping fails -> restart
  Master->>Svc: terminate + restart
```

## Session Lifecycle

`session_service.py` owns session state transitions and finalization.

```mermaid
stateDiagram-v2
  [*] --> Online: create_session
  Online --> Online: heartbeat
  Online --> Offline: heartbeat key expires
  Offline --> Online: heartbeat recovered
  Online --> Closed: close_session
  Offline --> Closed: hard_ttl expired
  Closed --> [*]
```

## Authentication and Connection Flow

```mermaid
sequenceDiagram
  participant C as Client App
  participant API as client-connect API
  participant Auth as auth_service
  participant WG as wg_manager
  participant IPAM as ipam_service
  participant Sess as session_service

  C->>API: GET /auth/pubkey
  C->>API: POST /auth/login (encrypted payload)
  API->>Auth: login via UDS
  Auth-->>API: tokens + device_id
  API-->>C: access/refresh tokens

  C->>API: POST /vpn/initiate (JWT + public_key)
  API->>WG: add_peer
  WG->>IPAM: allocate vpn_ip + tor_ip
  WG->>Sess: create_session (async task)
  WG-->>API: vpn_ip, tor_ip, server pubkeys, TTLs
  API-->>C: connection bundle
```

## Key and Secret Rotation Topology

```mermaid
flowchart LR
  KR["key_rotator"]
  Keys["/opt/tornado/keys/jwt"]
  Overlap["/opt/tornado/keys/jwt/overlap"]
  Auth["auth_service"]
  ClientAPI["client-connect API"]
  AdminAPI["admin-dashboard API"]
  Env["/opt/tornado/.env (ADMIN_SECRET)"]

  KR --> Keys
  KR --> Overlap
  KR --> Env
  KR -->|SIGHUP via pid files| Auth
  KR -->|SIGHUP via pid files| AdminAPI
  Auth -->|reload_keys| Keys
  ClientAPI -->|verify token| Keys
```

## Data Stores and Ownership

- Redis session keys: `vpn:session:*`
- Redis heartbeat sentinels: `vpn:session:*:hb`
- Redis IP pools: `vpn:ipam:pool:vpn`, `vpn:ipam:pool:tor`
- Redis live event channel: `vpn:live_events`
- Redis user event channel: `vpn:user_events`
- Redis revocation keys: `revoked_jti:*`
- PostgreSQL tables: `users`, `auth_sessions`, `wg_sessions`, `vpn_session_history`

## Operational Ports and Endpoints

- Admin API bind: `127.0.0.1:8000` (proxied by NGINX)
- Client API bind: `0.0.0.0:4605`
- WireGuard listener ports: `51820` (`wg0`) and `51821` (`wg1`)
- Tor defaults: TransPort `9040`, DNSPort `9053`, control `9051`, maintenance `9041`

## Design Constraints and Tradeoffs

- UDS-first service communication reduces network exposure but keeps services host-coupled.
- Redis keyspace event dependence requires `notify-keyspace-events Ex` to be configured.
- `wg_manager` and `session_service` run as root for network and interface operations.
- Key rotation uses file-based primitives and signal-driven reload; correctness depends on consistent pid file management.
