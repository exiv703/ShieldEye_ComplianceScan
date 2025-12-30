from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
from pathlib import Path
import logging

logger = logging.getLogger("shieldeye.templates")

@dataclass
class ScanTemplate:
    name: str
    description: str
    standards: List[str]
    mode: str
    max_pages: int
    max_depth: int
    timeout: int
    verify_ssl: bool
    checks_enabled: Dict[str, bool] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "standards": self.standards,
            "mode": self.mode,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
            "checks_enabled": self.checks_enabled,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> ScanTemplate:
        return cls(**data)

class ScanTemplateManager:
    
    BUILTIN_TEMPLATES = {
        "quick_gdpr": ScanTemplate(
            name="Quick GDPR Compliance",
            description="Fast GDPR compliance check for websites",
            standards=["GDPR"],
            mode="Quick/Safe",
            max_pages=10,
            max_depth=2,
            timeout=10,
            verify_ssl=False,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "cookies": True,
                "privacy_policy": True,
                "cookie_consent": True
            },
            tags=["gdpr", "privacy", "quick"]
        ),
        
        "full_gdpr": ScanTemplate(
            name="Full GDPR Audit",
            description="Comprehensive GDPR compliance audit",
            standards=["GDPR"],
            mode="Aggressive/Full",
            max_pages=100,
            max_depth=5,
            timeout=30,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "cookies": True,
                "privacy_policy": True,
                "cookie_consent": True,
                "data_processing": True,
                "third_party_tracking": True
            },
            tags=["gdpr", "privacy", "comprehensive"]
        ),
        
        "pci_dss_ecommerce": ScanTemplate(
            name="PCI-DSS E-commerce",
            description="PCI-DSS compliance for e-commerce sites",
            standards=["PCI-DSS"],
            mode="Aggressive/Full",
            max_pages=50,
            max_depth=4,
            timeout=20,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "forms": True,
                "payment_security": True,
                "encryption": True,
                "secure_transmission": True
            },
            tags=["pci-dss", "ecommerce", "payment"]
        ),
        
        "iso27001_security": ScanTemplate(
            name="ISO 27001 Security Audit",
            description="ISO 27001 information security audit",
            standards=["ISO 27001"],
            mode="Aggressive/Full",
            max_pages=75,
            max_depth=4,
            timeout=25,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "cookies": True,
                "access_control": True,
                "encryption": True,
                "security_policies": True
            },
            tags=["iso27001", "security", "audit"]
        ),
        
        "multi_compliance": ScanTemplate(
            name="Multi-Standard Compliance",
            description="Check against GDPR, PCI-DSS, and ISO 27001",
            standards=["GDPR", "PCI-DSS", "ISO 27001"],
            mode="Aggressive/Full",
            max_pages=100,
            max_depth=5,
            timeout=30,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "cookies": True,
                "forms": True,
                "privacy_policy": True,
                "payment_security": True,
                "access_control": True
            },
            tags=["multi-standard", "comprehensive"]
        ),
        
        "security_headers": ScanTemplate(
            name="Security Headers Check",
            description="Focus on HTTP security headers",
            standards=[],
            mode="Quick/Safe",
            max_pages=5,
            max_depth=1,
            timeout=10,
            verify_ssl=False,
            checks_enabled={
                "headers": True,
                "ssl": True
            },
            tags=["headers", "security", "quick"]
        ),
        
        "ssl_tls_audit": ScanTemplate(
            name="SSL/TLS Security Audit",
            description="Comprehensive SSL/TLS configuration check",
            standards=[],
            mode="Quick/Safe",
            max_pages=5,
            max_depth=1,
            timeout=15,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "certificate": True,
                "cipher_suites": True,
                "protocol_versions": True
            },
            tags=["ssl", "tls", "encryption"]
        ),
        
        "cookie_privacy": ScanTemplate(
            name="Cookie & Privacy Audit",
            description="Focus on cookies and privacy compliance",
            standards=["GDPR"],
            mode="Quick/Safe",
            max_pages=20,
            max_depth=3,
            timeout=15,
            verify_ssl=False,
            checks_enabled={
                "cookies": True,
                "privacy_policy": True,
                "cookie_consent": True,
                "third_party_tracking": True
            },
            tags=["cookies", "privacy", "gdpr"]
        ),
        
        "form_security": ScanTemplate(
            name="Form Security Audit",
            description="Check form security and data transmission",
            standards=["PCI-DSS"],
            mode="Aggressive/Full",
            max_pages=30,
            max_depth=3,
            timeout=20,
            verify_ssl=True,
            checks_enabled={
                "forms": True,
                "ssl": True,
                "csrf": True,
                "input_validation": True
            },
            tags=["forms", "security", "input"]
        ),
        
        "api_security": ScanTemplate(
            name="API Security Scan",
            description="Security scan for REST APIs",
            standards=["ISO 27001"],
            mode="Quick/Safe",
            max_pages=10,
            max_depth=2,
            timeout=15,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "authentication": True,
                "rate_limiting": True,
                "cors": True
            },
            tags=["api", "security", "rest"]
        ),
        
        "penetration_test_prep": ScanTemplate(
            name="Penetration Test Preparation",
            description="Pre-pentest reconnaissance and vulnerability identification",
            standards=["GDPR", "PCI-DSS", "ISO 27001"],
            mode="Aggressive/Full",
            max_pages=150,
            max_depth=6,
            timeout=30,
            verify_ssl=True,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "cookies": True,
                "forms": True,
                "tech_stack": True,
                "server_info": True,
                "directory_listing": True
            },
            tags=["pentest", "reconnaissance", "comprehensive"]
        ),
        
        "continuous_monitoring": ScanTemplate(
            name="Continuous Monitoring",
            description="Lightweight scan for continuous security monitoring",
            standards=["ISO 27001"],
            mode="Quick/Safe",
            max_pages=15,
            max_depth=2,
            timeout=10,
            verify_ssl=False,
            checks_enabled={
                "ssl": True,
                "headers": True,
                "availability": True
            },
            tags=["monitoring", "continuous", "lightweight"]
        )
    }
    
    def __init__(self, templates_file: Optional[Path] = None):
        self.templates_file = templates_file or Path.home() / ".shieldeye" / "templates.json"
        self.custom_templates: Dict[str, ScanTemplate] = {}
        self._load_templates()
    
    def _load_templates(self) -> None:
        if not self.templates_file.exists():
            return
        
        try:
            with open(self.templates_file, 'r') as f:
                data = json.load(f)
                for name, template_data in data.items():
                    self.custom_templates[name] = ScanTemplate.from_dict(template_data)
            logger.info(f"Loaded {len(self.custom_templates)} custom templates")
        except Exception as e:
            logger.error(f"Failed to load templates: {e}")
    
    def _save_templates(self) -> None:
        try:
            self.templates_file.parent.mkdir(parents=True, exist_ok=True)
            data = {name: template.to_dict() for name, template in self.custom_templates.items()}
            with open(self.templates_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save templates: {e}")
    
    def get_template(self, name: str) -> Optional[ScanTemplate]:
        if name in self.BUILTIN_TEMPLATES:
            return self.BUILTIN_TEMPLATES[name]
        return self.custom_templates.get(name)
    
    def list_templates(self, include_builtin: bool = True, tags: Optional[List[str]] = None) -> List[ScanTemplate]:
        templates = []
        
        if include_builtin:
            templates.extend(self.BUILTIN_TEMPLATES.values())
        
        templates.extend(self.custom_templates.values())
        
        if tags:
            templates = [t for t in templates if any(tag in t.tags for tag in tags)]
        
        return templates
    
    def create_template(self, template: ScanTemplate) -> None:
        self.custom_templates[template.name] = template
        self._save_templates()
        logger.info(f"Created template: {template.name}")
    
    def delete_template(self, name: str) -> bool:
        if name in self.custom_templates:
            del self.custom_templates[name]
            self._save_templates()
            logger.info(f"Deleted template: {name}")
            return True
        return False
    
    def get_template_by_tags(self, tags: List[str]) -> List[ScanTemplate]:
        return self.list_templates(include_builtin=True, tags=tags)
    
    def export_template(self, name: str, output_path: Path) -> None:
        template = self.get_template(name)
        if not template:
            raise ValueError(f"Template not found: {name}")
        
        with open(output_path, 'w') as f:
            json.dump(template.to_dict(), f, indent=2)
        logger.info(f"Exported template to {output_path}")
    
    def import_template(self, input_path: Path) -> ScanTemplate:
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        template = ScanTemplate.from_dict(data)
        self.create_template(template)
        return template

_template_manager: Optional[ScanTemplateManager] = None

def get_template_manager() -> ScanTemplateManager:
    global _template_manager
    if _template_manager is None:
        _template_manager = ScanTemplateManager()
    return _template_manager
