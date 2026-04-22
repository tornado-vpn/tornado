# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import signal

from utils.api_logging_utils import get_logger, get_context_logger

# ================= CONFIG =================
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_services.json")
SOCKET_PATH = "/run/tornado/api_mgr.sock"

logger = get_logger()


# ================================================================== #
#  UvicornApp — manages a single uvicorn process
# ================================================================== #

class UvicornApp:
    """
    Manages a single uvicorn process.

    Lifecycle
    ---------
    start()   → spawns the process, starts _watch_process + _monitor_health
    stop()    → cancels tasks, terminates process
    restart() → stop() + delay + start()

    Config hot-reload
    -----------------
    update_config() updates fields in-place. A restart is required for
    cmd / cwd changes to take effect — the caller (sync_apps) is
    responsible for deciding whether to restart.

    Crash recovery
    --------------
    _watch_process detects an unexpected exit and schedules
    _delayed_restart() via create_task so it can return immediately,
    avoiding a circular cancel chain when stop() cancels this task.

    Health monitoring
    -----------------
    _monitor_health polls health_url with curl every HEALTH_INTERVAL
    seconds. After HEALTH_RETRIES consecutive failures it schedules a
    restart the same way.

    Circuit breaker
    ---------------
    _circuit_breaker_trip() refuses further restarts once MAX_RESTARTS
    occur within RESTART_WINDOW seconds.
    """

    HEALTH_INTERVAL = 15
    HEALTH_TIMEOUT  = 10
    HEALTH_RETRIES  = 3
    MAX_RESTARTS    = 5
    RESTART_WINDOW  = 60.0

    def __init__(self, name: str, cfg: dict):
        self.name = name
        self.process: asyncio.subprocess.Process | None = None
        self.should_run:    bool = False
        self.is_restarting: bool = False

        self._watch_task:  asyncio.Task | None = None
        self._health_task: asyncio.Task | None = None

        # circuit breaker
        self._restart_count     = 0
        self._last_restart_time = 0.0

        # Per-app context logger: every log from this instance carries "app": name
        self._log = get_context_logger(app_name=name)

        self.update_config(cfg)

    def update_config(self, cfg: dict):
        self.cmd           = cfg["cmd"]
        self.cwd           = cfg.get("cwd", "/")
        self.health_url    = cfg.get("health_url", "")
        self.restart_delay = cfg.get("restart_delay", 3)
        self.description   = cfg.get("description", "")

    # ------------------------------------------------------------------ #
    #  Circuit breaker
    # ------------------------------------------------------------------ #

    def _circuit_breaker_trip(self) -> bool:
        now = asyncio.get_event_loop().time()
        if now - self._last_restart_time < self.RESTART_WINDOW:
            self._restart_count += 1
        else:
            self._restart_count = 1
        self._last_restart_time = now

        if self._restart_count > self.MAX_RESTARTS:
            self._log.critical(
                "circuit_breaker_tripped",
                extra={"extra_fields": {
                    "restart_count": self._restart_count,
                    "restart_window_seconds": self.RESTART_WINDOW,
                }}
            )
            self.should_run = False
            return True
        return False

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    async def start(self):
        if self.process and self.process.returncode is None:
            self._log.info(
                "app_already_running",
                extra={"extra_fields": {"pid": self.process.pid}}
            )
            return

        self.should_run    = True
        self.is_restarting = False
        self._log.info(
            "app_starting",
            extra={"extra_fields": {"cmd": " ".join(self.cmd)}}
        )

        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.cmd,
                cwd=self.cwd,
                env=os.environ.copy(),
                stdout=None,
                stderr=None,
            )
            self._log.info(
                "app_spawned",
                extra={"extra_fields": {"pid": self.process.pid}}
            )
        except Exception as exc:
            self._log.error(
                "app_spawn_failed",
                extra={"extra_fields": {"error": str(exc)}}
            )
            self.should_run = False
            return

        await self._cancel_tasks()
        self._watch_task  = asyncio.create_task(self._watch_process())
        self._health_task = asyncio.create_task(self._monitor_health())

    async def stop(self):
        self._log.info("app_stopping")
        self.should_run = False
        await self._cancel_tasks()

        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=8.0)
                self._log.info("app_terminated_gracefully")
            except asyncio.TimeoutError:
                self._log.warning("app_graceful_stop_timeout_killing")
                self.process.kill()
                await self.process.wait()

    async def restart(self):
        self._log.info("app_restarting")
        await self.stop()
        await asyncio.sleep(self.restart_delay)
        await self.start()

    # ------------------------------------------------------------------ #
    #  Status
    # ------------------------------------------------------------------ #

    def get_status(self) -> dict:
        running = self.process is not None and self.process.returncode is None
        if running:
            state = "running"
        elif self.should_run:
            state = "crashed"
        else:
            state = "stopped"

        return {
            "name":          self.name,
            "description":   self.description,
            "state":         state,
            "pid":           self.process.pid if self.process else None,
            "restart_count": self._restart_count,
            "health_url":    self.health_url,
        }

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    async def _cancel_tasks(self):
        tasks = []
        for attr in ("_health_task", "_watch_task"):
            t = getattr(self, attr)
            if t and not t.done():
                t.cancel()
                tasks.append(t)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._health_task = None
        self._watch_task  = None

    async def _watch_process(self):
        try:
            if not self.process:
                return
            await self.process.wait()

            if self.should_run and not self.is_restarting:
                self.is_restarting = True
                self._log.error(
                    "app_crashed",
                    extra={"extra_fields": {"exit_code": self.process.returncode}}
                )
                asyncio.create_task(self._delayed_restart())
        except asyncio.CancelledError:
            return

    async def _delayed_restart(self):
        if self._circuit_breaker_trip():
            return
        await asyncio.sleep(self.restart_delay)
        await self.start()

    async def _monitor_health(self):
        # Give the process time to bind its port before the first check.
        await asyncio.sleep(self.HEALTH_INTERVAL)

        consecutive_failures = 0
        try:
            while self.should_run:
                if not self.process or self.process.returncode is not None:
                    break

                healthy = await self._http_health_check()
 
                if healthy:
                    if consecutive_failures > 0:
                        self._log.info(
                            "health_check_recovered",
                            extra={"extra_fields": {"previous_failures": consecutive_failures}}
                        )
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    self._log.warning(
                        "health_check_failed",
                        extra={"extra_fields": {
                            "attempt": consecutive_failures,
                            "max_retries": self.HEALTH_RETRIES,
                            "health_url": self.health_url,
                        }}
                    )
                    if consecutive_failures >= self.HEALTH_RETRIES:
                        self._log.error(
                            "health_check_all_retries_exhausted",
                            extra={"extra_fields": {"retries": self.HEALTH_RETRIES}}
                        )
                        if not self.is_restarting and self.should_run:
                            self.is_restarting = True
                            asyncio.create_task(self._circuit_checked_restart())
                        break

                await asyncio.sleep(self.HEALTH_INTERVAL)

        except asyncio.CancelledError:
            return

    async def _circuit_checked_restart(self):
        if self._circuit_breaker_trip():
            return
        await self.restart()

    async def _http_health_check(self) -> bool:
        if not self.health_url:
            return True
        try:
            loop = asyncio.get_running_loop()
            import urllib.request
            def _do_get():
                with urllib.request.urlopen(self.health_url, timeout=self.HEALTH_TIMEOUT) as r:
                    return r.status == 200
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _do_get),
                timeout=self.HEALTH_TIMEOUT + 2
            )
            return result
        except Exception as e:
            self._log.warning(
                "health_check_exception",
                extra={"extra_fields": {"error": str(e), "health_url": self.health_url}}
            )
            return False


# ================================================================== #
#  App registry
# ================================================================== #

apps: dict[str, UvicornApp] = {}


# ================================================================== #
#  Config loading + hot-reload sync
# ================================================================== #

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
    except Exception as exc:
        logger.error(
            "config_parse_failed",
            extra={"extra_fields": {"error": str(exc)}}
        )
        return {}


async def sync_apps():
    configs = load_config()
    logger.info(
        "config_sync_started",
        extra={"extra_fields": {"app_count": len(configs)}}
    )

    for name, cfg in configs.items():
        enabled = cfg.get("enabled", True)

        if not enabled:
            if name in apps:
                logger.info(
                    "app_disabled_stopping",
                    extra={"extra_fields": {"app": name}}
                )
                await apps[name].stop()
                del apps[name]
            continue

        if name not in apps:
            apps[name] = UvicornApp(name, cfg)
            await apps[name].start()
        else:
            apps[name].update_config(cfg)
            logger.info(
                "app_config_updated",
                extra={"extra_fields": {"app": name, "note": "restart_required_for_cmd_cwd_changes"}}
            )

    for name in set(apps.keys()) - set(configs.keys()):
        logger.info(
            "app_removed_from_config",
            extra={"extra_fields": {"app": name}}
        )
        await apps[name].stop()
        del apps[name]

    logger.info("config_sync_complete")


async def stop_all():
    logger.info("stopping_all_apps", extra={"extra_fields": {"count": len(apps)}})
    for app in apps.values():
        await app.stop()


# ================================================================== #
#  Unix socket command handler
# ================================================================== #

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
    except asyncio.TimeoutError:
        writer.close()
        return

    if not data:
        writer.close()
        return

    response: dict = {"status": "error", "message": "Unknown command"}

    try:
        req    = json.loads(data.decode())
        cmd    = req.get("command") or req.get("action")
        target = req.get("target")

        logger.info(
            "command_received",
            extra={"extra_fields": {"command": cmd, "target": target or "all"}}
        )

        if cmd == "ping":
            response = {"status": "pong"}

        elif cmd == "reload_config":
            await sync_apps()
            response = {"status": "ok", "message": "Config reloaded from disk."}

        elif cmd == "list":
            response = {
                "status": "ok",
                "data": {
                    n: {
                        "description": a.description,
                        "health_url":  a.health_url,
                        "enabled":     a.should_run,
                    }
                    for n, a in apps.items()
                },
            }

        elif cmd == "status":
            if target and target != "all" and target in apps:
                response = {"status": "ok",
                            "data": {target: apps[target].get_status()}}
            else:
                response = {"status": "ok",
                            "data": {n: a.get_status() for n, a in apps.items()}}

        elif cmd in ("start", "stop", "restart"):
            if not target:
                response = {"status": "error", "message": "No 'target' specified."}
            else:
                targets = list(apps.keys()) if target == "all" else [target]
                missing = [t for t in targets if t not in apps]
                if missing:
                    logger.warning(
                        "command_unknown_targets",
                        extra={"extra_fields": {"command": cmd, "missing": missing}}
                    )
                    response = {"status": "error",
                                "message": f"Unknown apps: {missing}"}
                else:
                    for t in targets:
                        if cmd == "start":
                            await apps[t].start()
                        elif cmd == "stop":
                            await apps[t].stop()
                        elif cmd == "restart":
                            await apps[t].restart()
                    logger.info(
                        "command_issued",
                        extra={"extra_fields": {"command": cmd, "targets": targets}}
                    )
                    response = {"status": "ok",
                                "message": f"{cmd} issued to: {targets}"}

        else:
            logger.warning(
                "unknown_command",
                extra={"extra_fields": {"command": cmd}}
            )
            response = {"status": "error",
                        "message": f"Unknown command: '{cmd}'"}

    except json.JSONDecodeError:
        logger.warning("invalid_json_payload")
        response = {"status": "error", "message": "Invalid JSON payload."}
    except Exception as exc:
        logger.error(
            "command_handler_exception",
            extra={"extra_fields": {"error": str(exc)}},
            exc_info=True
        )
        response = {"status": "error", "message": str(exc)}

    try:
        writer.write(json.dumps(response).encode())
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


# ================================================================== #
#  Entry point
# ================================================================== #

stop_event = asyncio.Event()


async def main():
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    logger.info("service_starting", extra={"extra_fields": {"socket": SOCKET_PATH}})
    await sync_apps()

    socket_dir = os.path.dirname(SOCKET_PATH)
    os.makedirs(socket_dir, exist_ok=True)

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o660)

    logger.info("service_online", extra={"extra_fields": {"socket": SOCKET_PATH}})

    async with server:
        await stop_event.wait()
        logger.info("shutdown_signal_received")

    await stop_all()
    logger.info("service_stopped_cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("service_shutdown", extra={"extra_fields": {"reason": "keyboard_interrupt"}})
