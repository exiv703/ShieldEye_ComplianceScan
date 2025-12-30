from __future__ import annotations

import pytest
import tempfile
from pathlib import Path
from backend.database import ScanDatabase

class TestScanDatabase:

    @pytest.fixture
    def db(self):

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield ScanDatabase(db_path)
    
    def test_create_scan(self, db):

        db.create_scan(
            scan_id="test-123",
            url="https://example.com",
            mode="Quick/Safe",
            standards=["GDPR"]
        )
        
        scan = db.get_scan("test-123")
        assert scan is not None
        assert scan["url"] == "https://example.com"
        assert scan["mode"] == "Quick/Safe"
    
    def test_update_scan(self, db):

        db.create_scan(
            scan_id="test-123",
            url="https://example.com",
            mode="Quick/Safe",
            standards=[]
        )
        
        db.update_scan(
            scan_id="test-123",
            status="completed",
            score=85,
            counts={"critical": 0, "high": 1, "medium": 2, "low": 3}
        )
        
        scan = db.get_scan("test-123")
        assert scan["status"] == "completed"
        assert scan["score"] == 85
        assert scan["high_count"] == 1
    
    def test_add_finding(self, db):

        db.create_scan(
            scan_id="test-123",
            url="https://example.com",
            mode="Quick/Safe",
            standards=[]
        )
        
        db.add_finding(
            scan_id="test-123",
            severity="high",
            message="Missing security header",
            category="headers"
        )
        
        findings = db.get_findings("test-123")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
    
    def test_get_scans(self, db):

        db.create_scan("scan-1", "https://example1.com", "Quick/Safe", [])
        db.create_scan("scan-2", "https://example2.com", "Aggressive/Full", [])
        
        scans = db.get_scans(limit=10)
        assert len(scans) == 2
    
    def test_delete_scan(self, db):

        db.create_scan("test-123", "https://example.com", "Quick/Safe", [])
        
        deleted = db.delete_scan("test-123")
        assert deleted is True
        
        scan = db.get_scan("test-123")
        assert scan is None
    
    def test_get_statistics(self, db):

        db.create_scan("scan-1", "https://example.com", "Quick/Safe", [])
        db.update_scan("scan-1", status="completed", score=90)
        
        stats = db.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["completed_scans"] == 1

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
