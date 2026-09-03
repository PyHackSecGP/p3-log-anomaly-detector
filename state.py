"""
Persistent watch-mode state via SQLite.

Stores:
- Seen anomaly IDs per log file (no duplicate alerts across restarts)
- File read position + inode (tail-based scanning, survives log rotation)
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "p3-anomaly" / "state.db"


class WatchState:
    """
    SQLite-backed watch state.

    Persists file positions and seen anomaly IDs so the daemon survives
    restarts without re-alerting on stale findings or re-reading old bytes.
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        """
        Args:
            db_path: Path to the SQLite database file.
        """
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self._init_db()

    def _init_db(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS seen_anomalies (
                anomaly_id  TEXT NOT NULL,
                log_file    TEXT NOT NULL,
                seen_at     TEXT NOT NULL,
                PRIMARY KEY (anomaly_id, log_file)
            );
            CREATE TABLE IF NOT EXISTS file_positions (
                log_file    TEXT PRIMARY KEY,
                position    INTEGER NOT NULL DEFAULT 0,
                inode       INTEGER NOT NULL DEFAULT 0
            );
        """)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Anomaly deduplication
    # ------------------------------------------------------------------

    def is_seen(self, anomaly_id: str, log_file: str) -> bool:
        """Return True if this anomaly was already alerted in a previous scan."""
        row = self.conn.execute(
            "SELECT 1 FROM seen_anomalies WHERE anomaly_id = ? AND log_file = ?",
            (anomaly_id, log_file),
        ).fetchone()
        return row is not None

    def mark_seen(self, anomaly_id: str, log_file: str) -> None:
        """Record that an anomaly has been alerted."""
        self.conn.execute(
            "INSERT OR IGNORE INTO seen_anomalies (anomaly_id, log_file, seen_at) VALUES (?, ?, ?)",
            (anomaly_id, log_file, datetime.now().isoformat()),
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Tail-based file position tracking
    # ------------------------------------------------------------------

    def _get_position(self, log_file: str) -> tuple[int, int]:
        """Return (byte_position, inode) for the given log file."""
        row = self.conn.execute(
            "SELECT position, inode FROM file_positions WHERE log_file = ?",
            (log_file,),
        ).fetchone()
        return (row[0], row[1]) if row else (0, 0)

    def _save_position(self, log_file: str, position: int, inode: int) -> None:
        self.conn.execute(
            """
            INSERT INTO file_positions (log_file, position, inode)
            VALUES (?, ?, ?)
            ON CONFLICT (log_file) DO UPDATE SET position = excluded.position, inode = excluded.inode
            """,
            (log_file, position, inode),
        )
        self.conn.commit()

    def read_new_lines(self, log_file: str) -> list[str]:
        """
        Read only the lines appended since the last call.

        Handles log rotation: if the file's inode has changed or the file is
        smaller than our saved position, we reset to the beginning.

        Args:
            log_file: Absolute path to the log file being tailed.

        Returns:
            List of new raw log lines (including newline characters).
        """
        path = Path(log_file)
        if not path.is_file():
            return []

        stat = path.stat()
        current_inode = stat.st_ino
        current_size = stat.st_size

        last_pos, last_inode = self._get_position(log_file)

        # Log rotation: inode changed or file shrank
        if current_inode != last_inode or current_size < last_pos:
            last_pos = 0

        if current_size == last_pos:
            # Nothing new
            self._save_position(log_file, last_pos, current_inode)
            return []

        with open(log_file, "r", errors="replace") as fh:
            fh.seek(last_pos)
            new_lines = fh.readlines()
            new_pos = fh.tell()

        self._save_position(log_file, new_pos, current_inode)
        return new_lines
