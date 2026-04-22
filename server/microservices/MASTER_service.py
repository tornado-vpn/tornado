# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import os
import signal
import pwd
import grp

from utils.master_logging_utils import get_logger, get_context_logger

# ================= CONFIG =================
CONFIG_FILE = "services.json"
MASTER_SOCKET = "/run/tornado/master.sock"
SERVICE_GROUP = "tornado-services"

logger = get_logger()


class ServiceHandler:
    def __init__(self, name, config):
        self.name = name
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.process = None
        self.should_be_running = False
        self.health_check_task = None
        self.watch_task = None
        self.is_restarting = False
        self.env = {}
        self.update_config(config)

    def update_config(self, config):
        self.cmd = config["cmd"]
        self.socket_path = config["socket_path"]
        self.run_as_user = config.get("user", f"tornado-{self.name}")
        self.cwd = config.get("cwd", self.base_dir)
        self.env = config.get("env", {})

    def _log(self, **ctx):
        """Return a context logger pre-seeded with this service's name and PID."""
        pid = self.process.pid if self.process else None
        return get_context_logger(service_name=self.name, pid=pid, **ctx)

    def get_status(self):
        if self.process and self.process.returncode is None:
            state = "running"
        elif self.should_be_running:
            state = "crashed"
        else:
            state = "stopped"

        return {
            "name": self.name,
            "state": state,
            "pid": self.process.pid if self.process else None,
            "should_be_running": self.should_be_running,
        }

    async def start(self):
        log = self._log()

        if self.process and self.process.returncode is None:
            log.info("Service already running")
            return

        try:
            pw_record  = pwd.getpwnam(self.run_as_user)
            target_uid = pw_record.pw_uid
            target_gid = pw_record.pw_gid

            socket_dir = os.path.dirname(self.socket_path)
            os.makedirs(socket_dir, mode=0o775, exist_ok=True)

            try:
                ginfo = grp.getgrnam(SERVICE_GROUP)
                os.chown(socket_dir, 0, ginfo.gr_gid)
                os.chmod(socket_dir, 0o2775)
            except KeyError:
                log.warning(
                    "Shared group not found, falling back to service user ownership",
                    extra={"extra_fields": {"group": SERVICE_GROUP}},
                )
                os.chown(socket_dir, target_uid, target_gid)

            def drop_privileges():
                os.setgid(target_gid)
                os.setuid(target_uid)

            log.info(
                "Starting service",
                extra={"extra_fields": {"run_as_user": self.run_as_user}},
            )
            self.should_be_running = True
            self.is_restarting = False

            full_env = {**os.environ, **self.env}

            self.process = await asyncio.create_subprocess_exec(
                *self.cmd,
                cwd=self.cwd,
                env=full_env,
                preexec_fn=drop_privileges,
                stdout=None,
                stderr=None,
            )

            await self._cancel_tasks()
            self.watch_task        = asyncio.create_task(self._watch_process())
            self.health_check_task = asyncio.create_task(self._monitor_health())

            # Re-build log with the now-known PID
            self._log().info("Service started")

        except KeyError:
            get_context_logger(service_name=self.name).error(
                "System user does not exist",
                extra={"extra_fields": {"run_as_user": self.run_as_user}},
            )
            self.should_be_running = False
        except Exception as e:
            get_context_logger(service_name=self.name).error(
                "Failed to start service",
                extra={"extra_fields": {"error": str(e)}},
                exc_info=True,
            )
            self.should_be_running = False

    async def _cancel_tasks(self):
        tasks = []
        if self.health_check_task and not self.health_check_task.done():
            self.health_check_task.cancel()
            tasks.append(self.health_check_task)
        if self.watch_task and not self.watch_task.done():
            self.watch_task.cancel()
            tasks.append(self.watch_task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self.health_check_task = None
        self.watch_task = None

    async def stop(self):
        log = self._log()
        log.info("Stopping service")
        self.should_be_running = False

        await self._cancel_tasks()

        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("Graceful shutdown timed out — force killing")
                self.process.kill()
                await self.process.wait()

        log.info(
            "Service stopped",
            extra={"extra_fields": {"exit_code": self.process.returncode if self.process else None}},
        )

    async def restart(self):
        self._log().info("Restarting service")
        await self.stop()
        await asyncio.sleep(1)
        await self.start()

    async def _watch_process(self):
        try:
            if not self.process:
                return
            await self.process.wait()

            if self.should_be_running and not self.is_restarting:
                self.is_restarting = True
                self._log().error(
                    "Crash detected — scheduling restart",
                    extra={"extra_fields": {"exit_code": self.process.returncode}},
                )
                asyncio.create_task(self._delayed_restart())

        except asyncio.CancelledError:
            return

    async def _delayed_restart(self):
        await asyncio.sleep(2)
        await self.start()

    async def _monitor_health(self):
        log = self._log()
        try:
            while self.should_be_running:
                await asyncio.sleep(10)

                if not self.process or self.process.returncode is not None:
                    break

                try:
                    reader, writer = await asyncio.open_unix_connection(
                        path=self.socket_path
                    )
                    writer.write(json.dumps({"action": "ping"}).encode())
                    await writer.drain()

                    raw      = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    response = json.loads(raw.decode())
                    writer.close()
                    await writer.wait_closed()

                    if response.get("status") != "pong":
                        raise ValueError("Bad pong response")

                except Exception as e:
                    log.error(
                        "Heartbeat failed — scheduling restart",
                        extra={"extra_fields": {"error": str(e)}},
                    )
                    if not self.is_restarting and self.should_be_running:
                        self.is_restarting = True
                        asyncio.create_task(self.restart())
                    break

        except asyncio.CancelledError:
            log.debug("Health monitor cancelled")
            return


# ================= Global State =================
services: dict[str, ServiceHandler] = {}


def load_services_from_file():
    if not os.path.exists(CONFIG_FILE):
        logger.error(
            "Config file not found",
            extra={"extra_fields": {"config_file": CONFIG_FILE}},
        )
        return {}

    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(
            "Failed to parse config file",
            extra={"extra_fields": {"config_file": CONFIG_FILE, "error": str(e)}},
            exc_info=True,
        )
        return {}


async def sync_services():
    configs = load_services_from_file()

    for name, cfg in configs.items():
        slog = get_context_logger(service_name=name)

        if not cfg.get("enabled", True):
            if name in services:
                slog.info("Service disabled in config — stopping")
                await services[name].stop()
            continue

        if name not in services:
            services[name] = ServiceHandler(name, cfg)
            await services[name].start()
        else:
            slog.info("Updating service config")
            services[name].update_config(cfg)

    to_remove = set(services.keys()) - set(configs.keys())
    for name in to_remove:
        get_context_logger(service_name=name).info("Service removed from config — stopping")
        await services[name].stop()
        del services[name]


async def handle_admin_client(reader, writer):
    log = get_logger()
    try:
        data = await reader.read(4096)
        if not data:
            return

        req    = json.loads(data.decode())
        cmd    = req.get("command")
        target = req.get("target")

        # Per-request context logger
        rlog = get_context_logger(command=cmd, target=target)
        rlog.info("Admin command received")

        response = {"status": "ok"}

        if cmd == "reload_config":
            await sync_services()
            response["message"] = "Configuration reloaded from disk."

        elif cmd == "status":
            if target == "all":
                response["services"] = [h.get_status() for h in services.values()]
            elif target in services:
                response["services"] = [services[target].get_status()]
            else:
                response = {"status": "error", "message": f"Service '{target}' not found"}

        elif target in services or target == "all":
            targets = list(services.keys()) if target == "all" else [target]

            if cmd == "start":
                for t in targets:
                    await services[t].start()
                response["message"] = f"Started {', '.join(targets)}"
            elif cmd == "stop":
                for t in targets:
                    await services[t].stop()
                response["message"] = f"Stopped {', '.join(targets)}"
            elif cmd == "restart":
                for t in targets:
                    await services[t].restart()
                response["message"] = f"Restarted {', '.join(targets)}"
            else:
                response = {"status": "error", "message": f"Unknown command: {cmd}"}
        else:
            response = {"status": "error", "message": f"Unknown target: {target}"}

    except json.JSONDecodeError:
        response = {"status": "error", "message": "Invalid JSON"}
    except Exception as e:
        log.error(
            "Error handling admin client",
            extra={"extra_fields": {"error": str(e)}},
            exc_info=True,
        )
        response = {"status": "error", "message": str(e)}

    try:
        writer.write(json.dumps(response).encode())
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def shutdown():
    logger.info("Master shutting down — stopping all services")
    for handler in services.values():
        await handler.stop()


stop_event = asyncio.Event()


async def main():
    loop = asyncio.get_running_loop()

    for sig in [signal.SIGTERM, signal.SIGINT]:
        loop.add_signal_handler(sig, stop_event.set)

    logger.info(
        "Master starting",
        extra={"extra_fields": {"socket": MASTER_SOCKET, "config": CONFIG_FILE}},
    )

    await sync_services()

    server = await asyncio.start_unix_server(handle_admin_client, path=MASTER_SOCKET)
    os.chmod(MASTER_SOCKET, 0o660)

    logger.info("Master online", extra={"extra_fields": {"socket": MASTER_SOCKET}})

    async with server:
        await stop_event.wait()
        logger.info("Shutdown signal received")

    await shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Master interrupted by user")