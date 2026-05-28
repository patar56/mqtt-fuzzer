"""
Docker Broker Manager

Manages the lifecycle of the MQTT broker Docker container.
Supports starting, stopping, restarting, and health-checking the broker.
"""

import subprocess
import time
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

COMPOSE_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "docker", "docker-compose.yml"
)
CONTAINER_NAME = "mqtt_target_broker"


class DockerBrokerManager:
    """Manages the Mosquitto broker Docker container via subprocess."""

    def __init__(self, compose_file: Optional[str] = None):
        self.compose_file = compose_file or COMPOSE_FILE

    def _run(self, *args, capture: bool = True) -> subprocess.CompletedProcess:
        cmd = ["docker", *args]
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(f"Command failed: {' '.join(cmd)}")
            logger.warning(f"stderr: {result.stderr}")
        return result

    def _compose(self, *args) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-f", self.compose_file, *args]
        logger.debug(f"Compose: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def start_broker(self, wait_seconds: float = 3.0) -> bool:
        """Start the broker container via docker compose."""
        logger.info(f"Starting MQTT broker container: {CONTAINER_NAME}")
        result = self._compose("up", "-d", "mosquitto")
        if result.returncode == 0:
            logger.info(f"Broker starting — waiting {wait_seconds}s for readiness")
            time.sleep(wait_seconds)
            return self.is_container_running()
        logger.error(f"Failed to start broker: {result.stderr}")
        return False

    def stop_broker(self) -> bool:
        """Stop the broker container."""
        logger.info(f"Stopping broker container: {CONTAINER_NAME}")
        result = self._run("stop", CONTAINER_NAME)
        return result.returncode == 0

    def restart_broker(self) -> bool:
        """Restart the broker container."""
        logger.info(f"Restarting broker container: {CONTAINER_NAME}")
        result = self._run("restart", CONTAINER_NAME)
        if result.returncode == 0:
            time.sleep(2.0)
            return self.is_container_running()
        return False

    def is_container_running(self) -> bool:
        """Check if the container is running."""
        result = self._run(
            "inspect", "--format", "{{.State.Running}}", CONTAINER_NAME
        )
        return result.returncode == 0 and result.stdout.strip() == "true"

    def get_broker_logs(self, tail: int = 50) -> str:
        """Get recent broker container logs."""
        result = self._run("logs", "--tail", str(tail), CONTAINER_NAME)
        return result.stdout + result.stderr

    def get_broker_stats(self) -> dict:
        """Get container resource usage stats (one-shot)."""
        result = self._run(
            "stats", "--no-stream", "--format",
            "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}",
            CONTAINER_NAME,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("\t")
            return {
                "name": parts[0] if len(parts) > 0 else CONTAINER_NAME,
                "cpu": parts[1] if len(parts) > 1 else "N/A",
                "mem": parts[2] if len(parts) > 2 else "N/A",
            }
        return {"error": "Could not get stats", "running": self.is_container_running()}

    def pull_image(self, image: str = "eclipse-mosquitto:2.0.18") -> bool:
        """Pull a broker Docker image."""
        logger.info(f"Pulling image: {image}")
        result = self._run("pull", image, capture=False)
        return result.returncode == 0

    def setup(self) -> bool:
        """Full setup: ensure broker is running. Returns True if ready."""
        if self.is_container_running():
            logger.info(f"Broker container '{CONTAINER_NAME}' already running")
            return True
        return self.start_broker()
