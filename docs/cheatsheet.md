# Operator Quick Reference

This page is a practical command reference for day-to-day operations.

## Service Control

```bash
sudo systemctl status tornado --no-pager
sudo systemctl restart tornado
sudo systemctl stop tornado
sudo systemctl start tornado
```

## Core Dependency Health

```bash
sudo systemctl status postgresql --no-pager
sudo systemctl status redis-server --no-pager || sudo systemctl status redis --no-pager
sudo systemctl status nginx --no-pager
```

## API Health Checks

```bash
curl -sSf http://127.0.0.1:8000/health
curl -sSf http://127.0.0.1:4605/health
curl -sSf http://127.0.0.1:8000/ready
```

## WireGuard and Routing Checks

```bash
sudo wg show
ip link show wg0
ip link show wg1
ip route
sudo sysctl net.ipv4.ip_forward
```

## Tor and Relay Checks

```bash
sudo systemctl status tor --no-pager
curl -sS http://127.0.0.1:8000/network_state
curl -sS http://127.0.0.1:8000/relay/health
curl -sS http://127.0.0.1:8000/circuits
```

## Redis Diagnostics

```bash
redis-cli ping
redis-cli config get notify-keyspace-events
redis-cli --scan --pattern 'vpn:session:*' | head
redis-cli pubsub channels
```

## PostgreSQL Diagnostics

```bash
pg_isready -h 127.0.0.1 -p 5432
sudo -u postgres psql -c '\l'
sudo -u postgres psql -d tornadodb -c '\dt'
```

## Logs and Journal

```bash
sudo journalctl -u tornado -n 200 --no-pager
sudo journalctl -u tornado -f
sudo journalctl -u nginx -n 100 --no-pager
sudo journalctl -u postgresql -n 100 --no-pager
```

## Socket and Runtime Files

```bash
ls -l /run/tornado
ls -l /run/tornado/*.sock
ls -l /run/tornado/*.pid
```

## Common Incident Actions

### 1. Client Login Failures

```bash
curl -sSf http://127.0.0.1:4605/auth/pubkey
sudo journalctl -u tornado -n 300 --no-pager | grep -E 'login|auth|token|jwt'
```

### 2. VPN Initiation Failures

```bash
sudo journalctl -u tornado -n 300 --no-pager | grep -E 'wg_manager|ipam|session'
sudo wg show
```

### 3. Frequent Session Drops

```bash
redis-cli config get notify-keyspace-events
sudo journalctl -u tornado -n 300 --no-pager | grep -E 'heartbeat|offline|cleanup|expired'
```

### 4. Key Rotation Issues

```bash
ls -l /opt/tornado/keys/jwt
ls -l /opt/tornado/keys/jwt/overlap
sudo journalctl -u tornado -n 400 --no-pager | grep -E 'key_rotator|reload|sighup|jwt'
```

## Controlled Recovery Sequence

```bash
sudo systemctl restart postgresql
sudo systemctl restart redis-server || sudo systemctl restart redis
sudo systemctl restart tornado
sudo systemctl restart nginx
curl -sSf http://127.0.0.1:8000/health
curl -sSf http://127.0.0.1:4605/health
sudo wg show
```

## Data and Config Paths

- Runtime env: `/opt/tornado/.env`
- JWT keys: `/opt/tornado/keys/jwt/`
- Supervisor sockets/pids: `/run/tornado/`
- Server logs: `/var/log/tornado/`
- NGINX site config: `/etc/nginx/sites-available/admin-dashboard`

## Caution

- Avoid deleting files under `/opt/tornado/keys/jwt/` during active traffic.
- Avoid manually removing Redis session keys unless performing incident-directed cleanup.
- Prefer `systemctl restart tornado` over ad-hoc process kills to keep supervised state consistent.
