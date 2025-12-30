from __future__ import annotations

import pytest
from backend.validators import URLValidator, ScanConfigValidator, PathValidator
from backend.exceptions import ValidationError

class TestURLValidator:

    def test_valid_https_url(self):
        url = URLValidator.validate("https://example.com")
        assert url == "https://example.com"
    
    def test_valid_http_url(self):
        url = URLValidator.validate("http://example.com")
        assert url == "http://example.com"
    
    def test_url_without_scheme(self):
        url = URLValidator.validate("example.com")
        assert url == "https://example.com"
    
    def test_url_with_path(self):
        url = URLValidator.validate("https://example.com/path")
        assert url == "https://example.com/path"
    
    def test_empty_url(self):
        with pytest.raises(ValidationError):
            URLValidator.validate("")
    
    def test_invalid_scheme(self):
        url = URLValidator.validate("ftp://example.com")
        assert url == "https://ftp://example.com"
    
    def test_url_too_long(self):
        long_url = "https://example.com/" + "a" * 3000
        with pytest.raises(ValidationError):
            URLValidator.validate(long_url)
    
    def test_localhost_allowed(self):
        url = URLValidator.validate("http://localhost:8080", allow_localhost=True)
        assert url == "http://localhost:8080"
    
    def test_localhost_not_allowed(self):
        with pytest.raises(ValidationError):
            URLValidator.validate("http://localhost:8080", allow_localhost=False)

class TestScanConfigValidator:

    def test_valid_mode_quick(self):
        mode = ScanConfigValidator.validate_mode("Quick/Safe")
        assert mode == "Quick/Safe"
    
    def test_valid_mode_full(self):
        mode = ScanConfigValidator.validate_mode("Aggressive/Full")
        assert mode == "Aggressive/Full"
    
    def test_invalid_mode(self):
        with pytest.raises(ValidationError):
            ScanConfigValidator.validate_mode("Invalid")
    
    def test_valid_standards(self):
        standards = ScanConfigValidator.validate_standards(["GDPR", "PCI-DSS"])
        assert set(standards) == {"GDPR", "PCI-DSS"}
    
    def test_invalid_standard(self):
        with pytest.raises(ValidationError):
            ScanConfigValidator.validate_standards(["INVALID"])
    
    def test_empty_standards(self):
        standards = ScanConfigValidator.validate_standards([])
        assert standards == []
    
    def test_none_standards(self):
        standards = ScanConfigValidator.validate_standards(None)
        assert standards == []
    
    def test_valid_max_pages(self):
        max_pages = ScanConfigValidator.validate_max_pages(50)
        assert max_pages == 50
    
    def test_max_pages_too_large(self):
        with pytest.raises(ValidationError):
            ScanConfigValidator.validate_max_pages(2000)
    
    def test_max_pages_negative(self):
        with pytest.raises(ValidationError):
            ScanConfigValidator.validate_max_pages(-1)
    
    def test_valid_timeout(self):
        timeout = ScanConfigValidator.validate_timeout(30)
        assert timeout == 30
    
    def test_timeout_too_large(self):
        with pytest.raises(ValidationError):
            ScanConfigValidator.validate_timeout(500)

class TestPathValidator:

    def test_valid_pdf_path(self):
        path = PathValidator.validate_output_path("/tmp/report.pdf")
        assert path == "/tmp/report.pdf"
    
    def test_valid_json_path(self):
        path = PathValidator.validate_output_path("/tmp/data.json")
        assert path == "/tmp/data.json"
    
    def test_invalid_extension(self):
        with pytest.raises(ValidationError):
            PathValidator.validate_output_path("/tmp/file.txt")
    
    def test_path_with_traversal(self):
        with pytest.raises(ValidationError):
            PathValidator.validate_output_path("/tmp/../etc/passwd")
    
    def test_empty_path(self):
        with pytest.raises(ValidationError):
            PathValidator.validate_output_path("")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
