from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class SecurityMonitor:
    """Persist IDS alerts and tamper-evident SEAL-style security logs."""

    def __init__(self, base_dir: str, secret_key: bytes):
        self._base_dir = os.path.join(base_dir, "uploads", "security")
        self._ids_path = os.path.join(self._base_dir, "ids_logs.json")
        self._seal_path = os.path.join(self._base_dir, "seal_logs.json")
        self._secret_key = secret_key
        self._lock = threading.Lock()
        self._download_events: dict[str, deque[float]] = defaultdict(deque)
        self._request_events: dict[str, deque[float]] = defaultdict(deque)
        self._cooldowns: dict[str, float] = {}
        os.makedirs(self._base_dir, exist_ok=True)

    def _read_json(self, path: str) -> list[dict[str, Any]]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            return []
        if isinstance(payload, list):
            rows = [item for item in payload if isinstance(item, dict)]
            if self._ensure_row_ids(rows):
                self._write_json(path, rows)
            return rows
        return []

    def _ensure_row_ids(self, rows: list[dict[str, Any]]) -> bool:
        changed = False
        next_id = 1
        for row in rows:
            row_id = row.get("id")
            if isinstance(row_id, int) and row_id >= next_id:
                next_id = row_id + 1
        for row in rows:
            if not isinstance(row.get("id"), int):
                row["id"] = next_id
                next_id += 1
                changed = True
        return changed

    def _write_json(self, path: str, rows: list[dict[str, Any]]) -> None:
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=True, indent=2)
        os.replace(tmp_path, path)

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _next_id(self, rows: list[dict[str, Any]]) -> int:
        highest = 0
        for row in rows:
            row_id = row.get("id")
            if isinstance(row_id, int):
                highest = max(highest, row_id)
        return highest + 1

    def _seal_hash(self, user: str, action: str, timestamp: str, status: str) -> str:
        payload = f"{user}-{action}-{timestamp}-{status}".encode("utf-8")
        return hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()

    def add_ids_alert(self, user: str, action: str, severity: str = "medium") -> None:
        self.add_ids_alert_with_details(user, action, severity, "")

    def add_ids_alert_with_details(
        self,
        user: str,
        action: str,
        severity: str = "medium",
        details: str = "",
    ) -> None:
        with self._lock:
            rows = self._read_json(self._ids_path)
            rows.append(
                {
                    "id": self._next_id(rows),
                    "user": user or "anonymous",
                    "action": action,
                    "timestamp": self._utc_now(),
                    "severity": severity,
                    "status": "ALERT",
                    "details": details or "",
                }
            )
            self._write_json(self._ids_path, rows)

    def add_seal_log(
        self,
        user: str,
        action: str,
        status: str,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            rows = self._read_json(self._seal_path)
            timestamp = self._utc_now()
            rows.append(
                {
                    "id": self._next_id(rows),
                    "user": user or "anonymous",
                    "action": action,
                    "timestamp": timestamp,
                    "status": status,
                    "hash": self._seal_hash(user or "anonymous", action, timestamp, status),
                    "extra": extra or {},
                }
            )
            self._write_json(self._seal_path, rows)

    def recent_ids_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._read_json(self._ids_path)
        return list(reversed(rows[-limit:]))

    def recent_seal_logs(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._read_json(self._seal_path)
        return list(reversed(rows[-limit:]))

    def ids_alert_count(self) -> int:
        return len(self._read_json(self._ids_path))

    def seal_log_count(self) -> int:
        return len(self._read_json(self._seal_path))

    def get_ids_alert(self, alert_id: int) -> Optional[dict[str, Any]]:
        for row in self._read_json(self._ids_path):
            if row.get("id") == alert_id:
                return row
        return None

    def get_seal_log(self, log_id: int) -> Optional[dict[str, Any]]:
        for row in self._read_json(self._seal_path):
            if row.get("id") == log_id:
                return row
        return None

    def verify_seal_log_integrity(self, row: dict[str, Any]) -> bool:
        expected = self._seal_hash(
            row.get("user", "anonymous"),
            row.get("action", ""),
            row.get("timestamp", ""),
            row.get("status", ""),
        )
        return hmac.compare_digest(expected, row.get("hash", ""))

    def track_download(self, user: str) -> Optional[dict[str, str]]:
        return self._track_frequency(
            key=f"download:{user}",
            queue=self._download_events[user],
            threshold=5,
            window_seconds=60,
            action="MULTIPLE_DOWNLOADS",
            user=user,
            severity="medium",
            cooldown_seconds=60,
        )

    def track_request(self, actor: str) -> Optional[dict[str, str]]:
        return self._track_frequency(
            key=f"request:{actor}",
            queue=self._request_events[actor],
            threshold=25,
            window_seconds=10,
            action="RAPID_REQUESTS",
            user=actor,
            severity="medium",
            cooldown_seconds=30,
        )

    def _track_frequency(
        self,
        *,
        key: str,
        queue: deque[float],
        threshold: int,
        window_seconds: int,
        action: str,
        user: str,
        severity: str,
        cooldown_seconds: int,
    ) -> Optional[dict[str, str]]:
        now = time.time()
        queue.append(now)
        while queue and now - queue[0] > window_seconds:
            queue.popleft()
        if len(queue) <= threshold:
            return None
        last_alert_at = self._cooldowns.get(key, 0.0)
        if now - last_alert_at < cooldown_seconds:
            return None
        self._cooldowns[key] = now
        self.add_ids_alert_with_details(
            user,
            action,
            severity,
            f"Threshold exceeded: more than {threshold} events within {window_seconds} seconds.",
        )
        return {"user": user, "action": action, "severity": severity}
