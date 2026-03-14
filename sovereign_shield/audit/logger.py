"""
sovereign_shield/audit/logger.py

Sovereign Shield — Audit Logger
Append-only structured audit trail for all Shield decisions.
Enforces EU AI Act Art. 13 — Transparency & Logging Obligations.

Every PASS, HALT, and ERROR is written here.
This file is the legal evidence trail. It never deletes. It never overwrites.
Edit this file only if the log format needs to change.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path


# ── Log format constants ──────────────────────────────────────────────────────
LOG_VERSION    = "1.0"
SHIELD_NAME    = "sovereign-shield"
LOG_ENCODING   = "utf-8"


# ── Internal Python logger (stderr only — separate from audit file) ───────────
_internal = logging.getLogger("sovereign_shield.internal")


# ── Audit Logger ──────────────────────────────────────────────────────────────
class AuditLogger:
    """
    Append-only structured audit logger.

    Writes one JSON object per line (JSONL format).
    Every entry is timestamped in UTC and versioned.

    JSONL format means:
    - Each line is a valid, parseable JSON object
    - Easy to stream into SIEM tools (Splunk, Elastic, etc.)
    - Easy to grep, filter, and audit
    - Never corrupted by partial writes

    Usage:
        logger = AuditLogger()
        logger.log_pass(url="https://api.de", guard="GeoGuard", country="DE")
        logger.log_halt(url="https://api.cn", guard="GeoGuard", country="CN",
                        reason="Country not in EU adequacy list (Art.53)")
        logger.log_error(guard="PIIGuard", reason="Regex engine failed")
    """

    def __init__(self, log_path: str = "./shield_audit.log"):
        self.log_path = Path(log_path)
        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Create log file and parent directories if they don't exist."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.log_path.exists():
                self.log_path.touch()
        except OSError as e:
            _internal.error(f"Cannot create audit log at {self.log_path}: {e}")

    def _now_utc(self) -> str:
        """Returns current UTC timestamp in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def _base_entry(self, verdict: str, guard: str) -> dict:
        """Base fields present in every audit entry."""
        return {
            "shield"  : SHIELD_NAME,
            "version" : LOG_VERSION,
            "ts_utc"  : self._now_utc(),
            "verdict" : verdict,
            "guard"   : guard,
        }

    def _write(self, entry: dict) -> None:
        """
        Append one JSON line to the audit log.
        Atomic enough for single-process use.
        Never raises — Shield must not crash on logging failure.
        """
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            with open(self.log_path, "a", encoding=LOG_ENCODING) as f:
                f.write(line)
        except Exception as e:
            # Log to stderr only — never crash the Shield
            _internal.error(f"Audit write failed: {e} | entry={entry}")

    # ── Public API ────────────────────────────────────────────────────────────

    def log_pass(
        self,
        url    : str,
        guard  : str,
        **extra,
    ) -> None:
        """
        Log a PASS verdict — request allowed through.

        Args:
            url:   Destination URL of the outbound request
            guard: Name of the guard that issued the verdict
            extra: Any additional context (country, pii_type, etc.)
        """
        entry = self._base_entry("PASS", guard)
        entry["url"] = url
        entry.update(extra)
        self._write(entry)

    def log_halt(
        self,
        url    : str,
        guard  : str,
        reason : str,
        **extra,
    ) -> None:
        """
        Log a HALT verdict — request blocked.
        This is the primary legal evidence entry.

        Args:
            url:    Destination URL that was blocked
            guard:  Name of the guard that issued the HALT
            reason: Human-readable reason for the block
            extra:  Additional context (country, pii_type, article, etc.)
        """
        entry = self._base_entry("HALT", guard)
        entry["url"]    = url
        entry["reason"] = reason
        entry.update(extra)
        self._write(entry)

    def log_error(
        self,
        guard  : str,
        reason : str,
        **extra,
    ) -> None:
        """
        Log a Shield internal error.
        Shield fails CLOSED on errors — this records why.

        Args:
            guard:  Name of the guard where error occurred
            reason: Description of the error
            extra:  Any additional debug context
        """
        entry = self._base_entry("ERROR", guard)
        entry["reason"] = reason
        entry.update(extra)
        self._write(entry)

    def log_shield_event(self, event: str, detail: str = "") -> None:
        """
        Log a Shield lifecycle event.
        Used for install, uninstall, and startup events.

        Args:
            event:  Event name (e.g. 'shield_installed', 'shield_uninstalled')
            detail: Optional detail string
        """
        entry = self._base_entry("EVENT", "Shield")
        entry["event"]  = event
        entry["detail"] = detail
        self._write(entry)


# ── Module-level singleton ────────────────────────────────────────────────────
# Imported and used by all guards and the interceptor.
# Do not instantiate AuditLogger directly in other modules.
# Use: from sovereign_shield.audit.logger import audit_logger

audit_logger = AuditLogger()