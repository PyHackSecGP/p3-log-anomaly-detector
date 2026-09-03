"""
Rolling z-score baseline for statistical anomaly detection.

Records per-hour event counts in SQLite. Uses z-score against 30-day history
to determine whether a current count is statistically anomalous for THIS system
— not just globally high.

This turns "5 SSH failures = alert" into "5 SSH failures when you normally
see 0 at this hour = alert, but 5 when you normally see 200 = noise".
"""

from __future__ import annotations

import sqlite3
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent

DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "p3-anomaly" / "baseline.db"
_HISTORY_DAYS = 30
_MIN_SAMPLES = 3        # need at least this many days before z-score is meaningful
_Z_THRESHOLD = 2.5      # standard deviations above mean = anomalous


class Baseline:
    """
    SQLite-backed rolling baseline.

    Records hourly event-type counts and computes z-scores against the
    rolling 30-day history at the same hour of day.
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
            CREATE TABLE IF NOT EXISTS hourly_counts (
                day         TEXT    NOT NULL,
                hour        INTEGER NOT NULL,
                event_type  TEXT    NOT NULL,
                count       INTEGER NOT NULL,
                PRIMARY KEY (day, hour, event_type)
            );
            CREATE INDEX IF NOT EXISTS idx_hourly_etype_hour
                ON hourly_counts (event_type, hour);
        """)
        self.conn.commit()

    def record(self, events: list[LogEvent]) -> None:
        """
        Aggregate events by (day, hour, event_type) and upsert into baseline.

        Args:
            events: Parsed log events from the current scan window.
        """
        counts: dict[tuple[str, int, str], int] = defaultdict(int)
        for ev in events:
            if ev.timestamp and ev.event_type:
                key = (ev.timestamp.strftime("%Y-%m-%d"), ev.timestamp.hour, ev.event_type)
                counts[key] += 1

        self.conn.executemany(
            """
            INSERT INTO hourly_counts (day, hour, event_type, count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (day, hour, event_type)
            DO UPDATE SET count = count + excluded.count
            """,
            [(day, hour, etype, cnt) for (day, hour, etype), cnt in counts.items()],
        )
        self.conn.commit()

    def z_score(self, event_type: str, hour: int, current_count: int) -> Optional[float]:
        """
        Compute z-score of current_count vs 30-day same-hour history.

        Returns None if there is insufficient history (< MIN_SAMPLES days).

        Args:
            event_type: Log event type string (e.g. "ssh_failed_password").
            hour: Hour of day (0–23) for the current observation.
            current_count: Number of events of this type in the current window.
        """
        rows = self.conn.execute(
            """
            SELECT count FROM hourly_counts
            WHERE event_type = ? AND hour = ?
            ORDER BY day DESC LIMIT ?
            """,
            (event_type, hour, _HISTORY_DAYS),
        ).fetchall()

        if len(rows) < _MIN_SAMPLES:
            return None

        historical = [r[0] for r in rows]
        mean = statistics.mean(historical)
        try:
            stdev = statistics.stdev(historical)
        except statistics.StatisticsError:
            return None

        if stdev == 0:
            # All historical values are identical; any deviation is infinite z
            return float("inf") if current_count > mean else 0.0

        return (current_count - mean) / stdev

    def is_anomalous(
        self,
        event_type: str,
        hour: int,
        current_count: int,
        threshold: float = _Z_THRESHOLD,
    ) -> tuple[bool, Optional[float]]:
        """
        Return (is_anomalous, z_score).

        is_anomalous is True when z > threshold AND we have enough history.
        When history is insufficient, returns (False, None) — no false positives
        during the learning period.

        Args:
            event_type: Event type to check.
            hour: Hour of day for context.
            current_count: Current observation count.
            threshold: Z-score cutoff (default 2.5 ≈ 99th percentile).
        """
        z = self.z_score(event_type, hour, current_count)
        if z is None:
            return False, None
        return z > threshold, z

    def has_history(self, event_type: str) -> bool:
        """Return True if we have at least MIN_SAMPLES days of history for this event type."""
        count = self.conn.execute(
            "SELECT COUNT(DISTINCT day) FROM hourly_counts WHERE event_type = ?",
            (event_type,),
        ).fetchone()[0]
        return count >= _MIN_SAMPLES
