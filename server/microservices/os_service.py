# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
from pathlib import Path

from utils.os_logging_utils import get_logger, get_context_logger

# ================= CONFIG =================
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "os_services.json")
OS_SERVICE_SOCKET = "/run/tornado/os_services.sock"

logger = get_logger()


class HealthCheckStrategy:
    """
    Determines how to health-check a given OS service.
    Supports: tcp, http, process, command
    """

    @staticmethod
    async def tcp(host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    @staticmethod
    async def http(url: str, timeout: float = 5.0) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sf", "--max-time", str(int(timeout)), url,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
            return proc.returncode == 0
        except Exception:
            return False

    @staticmethod
    async def process(process_name: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "pgrep", "-x", process_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    @staticmethod
    async def command(cmd: list, timeout: float = 5.0) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout)
            return proc.returncode == 0
        except Exception:
            return False

    @staticmethod
    async def multi_command(cmds: list[list], timeout: float = 5.0) -> bool:
        """Run multiple commands — ALL must succeed for health to pass."""
        try:
            for cmd in cmds:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await asyncio.wait_for(proc.wait(), timeout=timeout)
                if proc.returncode != 0:
                    return False
            return True
        except Exception:
            return False


class OSServiceHandler:
    """
    Manages a single OS-level service (tor, haproxy, postgresql, etc.)

    Supports two management modes:
      - systemd: delegates start/stop/restart to systemctl
      - process: directly spawns and manages the process
    """

    def __init__(self, name: str, config: dict):
        self.name = name
        self.process = None
        self.should_be_running = False
        self.health_check_task = None
        self._restart_count = 0
        self._max_restarts = 5
        self._restart_window = 60.0
        self._last_restart_time = 0.0
        self.update_config(config)
        # Per-service context logger: every log from this handler includes "os_service": name
        self._log = get_context_logger(service_name=name)

    def update_config(self, config: dict):
        self.mode = config.get("mode", "systemd")
        self.systemd_unit = config.get("systemd_unit", self.name)
        self.cmd = config.get("cmd", [])
        self.cwd = config.get("cwd", "/")
        self.env = config.get("env", {})
        self.restart_on_failure = config.get("restart_on_failure", True)
        self.restart_delay = config.get("restart_delay", 3)
        self.health = config.get("health", {})
        self.description = config.get("description", "")
        self.logo_path = config.get("logo_path", "")

    # ------------------------------------------------------------------ #
    #  Circuit Breaker
    # ------------------------------------------------------------------ #

    def _circuit_breaker_trip(self) -> bool:
        now = asyncio.get_event_loop().time()
        if now - self._last_restart_time < self._restart_window:
            self._restart_count += 1
        else:
            self._restart_count = 1
        self._last_restart_time = now

        if self._restart_count > self._max_restarts:
            self._log.critical(
                "circuit_breaker_tripped",
                extra={"extra_fields": {
                    "restart_count": self._restart_count,
                    "restart_window_seconds": self._restart_window,
                }}
            )
            self.should_be_running = False
            return True
        return False

    # ------------------------------------------------------------------ #
    #  Start / Stop / Restart
    # ------------------------------------------------------------------ #

    async def start(self):
        self.should_be_running = True
        self._log.info(
            "service_starting",
            extra={"extra_fields": {"mode": self.mode}}
        )

        if self.mode == "systemd":
            already_running = await self._is_systemd_active()
        else:
            already_running = self.process is not None and self.process.returncode is None

        if already_running:
            self._log.info(
                "service_already_running_skipping_start",
                extra={"extra_fields": {"mode": self.mode}}
            )
        else:
            if self.mode == "systemd":
                await self._systemctl("start")
            elif self.mode == "process":
                await self._start_process()
            else:
                self._log.error(
                    "unknown_mode",
                    extra={"extra_fields": {"mode": self.mode}}
                )

        if self.health_check_task is None or self.health_check_task.done():
            self.health_check_task = asyncio.create_task(self._monitor_health())

    async def stop(self):
        self.should_be_running = False
        if self.health_check_task:
            self.health_check_task.cancel()
            self.health_check_task = None

        self._log.info("service_stopping")

        if self.mode == "systemd":
            await self._systemctl("stop")
        elif self.mode == "process":
            await self._stop_process()

    async def restart(self):
        self._log.info("service_restarting")
        if self.mode == "systemd":
            already_running = await self._is_systemd_active()
            self.should_be_running = True
            if already_running:
                await self._systemctl("restart")
            else:
                await self._systemctl("start")
        else:
            await self.stop()
            await asyncio.sleep(self.restart_delay)
            await self.start()

    # ------------------------------------------------------------------ #
    #  Internal: systemd
    # ------------------------------------------------------------------ #

    async def _systemctl(self, action: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", action, self.systemd_unit,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            if proc.returncode != 0:
                self._log.error(
                    "systemctl_failed",
                    extra={"extra_fields": {
                        "action": action,
                        "unit": self.systemd_unit,
                        "stderr": stderr.decode().strip(),
                    }}
                )
                return False
            self._log.info(
                "systemctl_success",
                extra={"extra_fields": {"action": action, "unit": self.systemd_unit}}
            )
            return True
        except Exception as e:
            self._log.error(
                "systemctl_exception",
                extra={"extra_fields": {"action": action, "error": str(e)}}
            )
            return False

    # ------------------------------------------------------------------ #
    #  Internal: direct process
    # ------------------------------------------------------------------ #

    async def _start_process(self):
        if self.process and self.process.returncode is None:
            self._log.warning(
                "process_already_running",
                extra={"extra_fields": {"pid": self.process.pid}}
            )
            return

        if not self.cmd:
            self._log.error("process_no_cmd_defined")
            return

        try:
            full_env = {**os.environ, **self.env}
            self.process = await asyncio.create_subprocess_exec(
                *self.cmd,
                cwd=self.cwd,
                env=full_env,
                stdout=None,
                stderr=None,
            )
            self._log.info(
                "process_spawned",
                extra={"extra_fields": {"pid": self.process.pid, "cmd": self.cmd[0]}}
            )
            asyncio.create_task(self._watch_process())
        except Exception as e:
            self._log.error(
                "process_spawn_failed",
                extra={"extra_fields": {"error": str(e)}}
            )
            self.should_be_running = False

    async def _stop_process(self):
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=8.0)
                self._log.info("process_terminated_gracefully")
            except asyncio.TimeoutError:
                self._log.warning("process_graceful_stop_timeout_killing")
                self.process.kill()
        self.process = None

    async def _watch_process(self):
        if not self.process:
            return
        await self.process.wait()

        if self.should_be_running and self.restart_on_failure:
            if self._circuit_breaker_trip():
                return

            self._log.error(
                "process_crashed",
                extra={"extra_fields": {
                    "restart_attempt": self._restart_count,
                    "restart_delay_seconds": self.restart_delay,
                }}
            )
            await asyncio.sleep(self.restart_delay)
            await self._start_process()

    # ------------------------------------------------------------------ #
    #  Health Monitoring
    # ------------------------------------------------------------------ #

    async def _monitor_health(self):
        interval = self.health.get("interval", 15)
        retries = self.health.get("retries", 3)

        while self.should_be_running:
            await asyncio.sleep(interval)

            healthy = False
            for attempt in range(1, retries + 1):
                healthy = await self._run_health_check()
                if healthy:
                    break
                self._log.warning(
                    "health_check_attempt_failed",
                    extra={"extra_fields": {"attempt": attempt, "max_retries": retries}}
                )
                await asyncio.sleep(2)

            if not healthy:
                self._log.error(
                    "health_check_all_retries_exhausted",
                    extra={"extra_fields": {"retries": retries}}
                )
                if self._circuit_breaker_trip():
                    break
                await self.restart()

    async def _run_health_check(self) -> bool:
        htype = self.health.get("type", "process")

        if htype == "tcp":
            return await HealthCheckStrategy.tcp(
                self.health.get("host", "127.0.0.1"),
                self.health["port"],
                self.health.get("timeout", 3.0)
            )
        elif htype == "http":
            return await HealthCheckStrategy.http(
                self.health["url"],
                self.health.get("timeout", 5.0)
            )
        elif htype == "process":
            return await HealthCheckStrategy.process(
                self.health.get("process_name", self.name)
            )
        elif htype == "command":
            return await HealthCheckStrategy.command(
                self.health["cmd"],
                self.health.get("timeout", 5.0)
            )
        elif htype == "multi_command":
            return await HealthCheckStrategy.multi_command(
                self.health["cmds"],
                self.health.get("timeout", 5.0)
            )
        else:
            self._log.warning(
                "unknown_health_check_type",
                extra={"extra_fields": {"type": htype}}
            )
            return True

    # ------------------------------------------------------------------ #
    #  Status
    # ------------------------------------------------------------------ #

    async def get_status(self) -> dict:
        if self.mode == "systemd":
            running = await self._is_systemd_active()
        else:
            if self.process is not None and self.process.returncode is None:
                running = True
            elif self.health:
                # no managed process, use health check as source of truth
                running = await self._run_health_check()
            else:
                running = False

        return {
            "name": self.name,
            "mode": self.mode,
            "description": self.description,
            "should_be_running": self.should_be_running,
            "running": running,
            "state": "RUNNING" if running else ("STOPPED" if not self.should_be_running else "CRASHED"),
            "restart_count": self._restart_count,
            "logo_path": self.logo_path,
        }

    async def _is_systemd_active(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", "--quiet", self.systemd_unit,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False


# ================================================================== #
#  Service Registry
# ================================================================== #

os_services: dict[str, OSServiceHandler] = {}


def load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        logger.error(
            "config_file_not_found",
            extra={"extra_fields": {"path": CONFIG_FILE}}
        )
        return {}
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(
            "config_parse_failed",
            extra={"extra_fields": {"error": str(e)}}
        )
        return {}


async def sync_services():
    """Hot-reload: diff JSON config against running services and apply changes."""
    configs = load_config()
    logger.info(
        "config_sync_started",
        extra={"extra_fields": {"service_count": len(configs)}}
    )

    for name, cfg in configs.items():
        enabled = cfg.get("enabled", True)

        if not enabled:
            if name in os_services:
                logger.info(
                    "service_disabled_stopping",
                    extra={"extra_fields": {"os_service": name}}
                )
                await os_services[name].stop()
                del os_services[name]
            continue

        if name not in os_services:
            os_services[name] = OSServiceHandler(name, cfg)
            await os_services[name].start()
        else:
            os_services[name].update_config(cfg)
            logger.info(
                "service_config_updated",
                extra={"extra_fields": {"os_service": name, "note": "restart_required_to_apply"}}
            )

    to_remove = set(os_services.keys()) - set(configs.keys())
    for name in to_remove:
        logger.info(
            "service_removed_from_config",
            extra={"extra_fields": {"os_service": name}}
        )
        await os_services[name].stop()
        del os_services[name]

    logger.info("config_sync_complete")


# ================================================================== #
#  Unix Socket Command Handler
# ================================================================== #

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    data = await reader.read(8192)
    if not data:
        writer.close()
        return

    response = {"status": "error", "message": "Unknown command"}

    try:
        req = json.loads(data.decode())
        cmd = req.get("command") or req.get("action")
        target = req.get("target")

        logger.info(
            "command_received",
            extra={"extra_fields": {"command": cmd, "target": target or "all"}}
        )

        if cmd == "reload_config":
            await sync_services()
            response = {"status": "ok", "message": "Config reloaded from disk."}

        elif cmd == "status":
            if target and target != "all" and target in os_services:
                response = {
                    "status": "ok",
                    "data": {target: await os_services[target].get_status()}
                }
            else:
                statuses = {}
                for name, handler in os_services.items():
                    statuses[name] = await handler.get_status()
                response = {"status": "ok", "data": statuses}

        elif cmd in ("start", "stop", "restart"):
            if not target:
                response = {"status": "error", "message": "No 'target' specified."}
            else:
                targets = list(os_services.keys()) if target == "all" else [target]
                missing = [t for t in targets if t not in os_services]
                if missing:
                    logger.warning(
                        "command_unknown_targets",
                        extra={"extra_fields": {"command": cmd, "missing": missing}}
                    )
                    response = {"status": "error", "message": f"Unknown services: {missing}"}
                else:
                    for t in targets:
                        if cmd == "start":
                            await os_services[t].start()
                        elif cmd == "stop":
                            await os_services[t].stop()
                        elif cmd == "restart":
                            await os_services[t].restart()
                    logger.info(
                        "command_issued",
                        extra={"extra_fields": {"command": cmd, "targets": targets}}
                    )
                    response = {"status": "ok", "message": f"{cmd} issued to: {targets}"}

        elif cmd == "list":
            response = {
                "status": "ok",
                "data": {
                    name: {
                        "mode": h.mode,
                        "description": h.description,
                        "enabled": h.should_be_running,
                        "logo_path": h.logo_path,
                    }
                    for name, h in os_services.items()
                }
            }

        elif cmd == "ping":
            response = {"status": "pong"}

        else:
            logger.warning(
                "unknown_command",
                extra={"extra_fields": {"command": cmd}}
            )
            response = {"status": "error", "message": f"Unknown command: '{cmd}'"}

    except json.JSONDecodeError:
        logger.warning("invalid_json_payload")
        response = {"status": "error", "message": "Invalid JSON payload."}
    except Exception as e:
        logger.error(
            "command_handler_exception",
            extra={"extra_fields": {"error": str(e)}},
            exc_info=True
        )
        response = {"status": "error", "message": str(e)}

    writer.write(json.dumps(response).encode())
    await writer.drain()
    writer.close()


# ================================================================== #
#  Entry Point
# ================================================================== #

async def main():
    logger.info("service_starting", extra={"extra_fields": {"socket": OS_SERVICE_SOCKET}})

    await sync_services()

    if os.path.exists(OS_SERVICE_SOCKET):
        os.remove(OS_SERVICE_SOCKET)

    socket_dir = os.path.dirname(OS_SERVICE_SOCKET)
    os.makedirs(socket_dir, exist_ok=True)

    server = await asyncio.start_unix_server(handle_client, path=OS_SERVICE_SOCKET)
    os.chmod(OS_SERVICE_SOCKET, 0o660)

    logger.info("service_online", extra={"extra_fields": {"socket": OS_SERVICE_SOCKET}})

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("service_shutdown", extra={"extra_fields": {"reason": "keyboard_interrupt"}})
