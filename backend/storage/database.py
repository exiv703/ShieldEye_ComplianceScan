from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from contextlib import contextmanager

from ..core.exceptions import DatabaseError
from ..utils.logging_config import get_logger

logger = get_logger("database")

class ScanDatabase:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}", exc_info=True)
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            conn.close()
    
    def _init_database(self) -> None:
        """Initialize database schema (tables and indexes only)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    standards TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_seconds REAL,
                    status TEXT DEFAULT 'running',
                    score INTEGER,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    pages_scanned INTEGER DEFAULT 0,
                    results_json TEXT,
                    error_message TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT,
                    message TEXT NOT NULL,
                    location TEXT,
                    standards TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS scan_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                """
            )
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return dict(row)
    
    def get_scans(
        self,
        limit: int = 100,
        offset: int = 0,
        url: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if url:
            query += " AND url = ?"
            params.append(url)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity",
                (scan_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_scan(self, scan_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scan_metadata WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            deleted = cursor.rowcount > 0
            
            if deleted:
                logger.info(f"Deleted scan: {scan_id}")
            
            return deleted
    
    def get_statistics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) as total FROM scans")
            total_scans = cursor.fetchone()["total"]
            
            cursor.execute("SELECT COUNT(*) as total FROM scans WHERE status = 'completed'")
            completed_scans = cursor.fetchone()["total"]
            
            cursor.execute("SELECT COUNT(*) as total FROM scans WHERE status = 'failed'")
            failed_scans = cursor.fetchone()["total"]
            
            cursor.execute("SELECT AVG(score) as avg_score FROM scans WHERE score IS NOT NULL")
            avg_score = cursor.fetchone()["avg_score"] or 0
            
            cursor.execute("SELECT SUM(critical_count) as total FROM scans")
            total_critical = cursor.fetchone()["total"] or 0
            
            cursor.execute("SELECT SUM(high_count) as total FROM scans")
            total_high = cursor.fetchone()["total"] or 0

            cursor.execute("SELECT SUM(medium_count) as total FROM scans")
            total_medium = cursor.fetchone()["total"] or 0

            cursor.execute("SELECT SUM(low_count) as total FROM scans")
            total_low = cursor.fetchone()["total"] or 0
            
            return {
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "failed_scans": failed_scans,
                "average_score": round(avg_score, 2),
                "total_critical_findings": total_critical,
                "total_high_findings": total_high,
                "total_medium_findings": total_medium,
                "total_low_findings": total_low,
            }
    
    def vacuum(self) -> None:
        with self._get_connection() as conn:
            conn.execute("VACUUM")
            logger.info("Database vacuumed")
