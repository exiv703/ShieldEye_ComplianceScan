from __future__ import annotations

from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import asyncio
import logging

try:
    from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks, Query, Request
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.responses import FileResponse, JSONResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    BaseModel = object
    Field = lambda *args, **kwargs: None

from ..core.backend import run_scan, analyze_scan_results
from ..storage.database import ScanDatabase
from ..security.auth import get_auth_manager, AuthenticationError, AuthorizationError
from ..utils.config import get_config
from ..reporting.exporters import export_scan
from ..utils.scan_templates import get_template_manager
from ..integrations.comparison import compare_scan_results
from ..integrations.scheduler import get_scheduler, ScheduleFrequency
from ..integrations.webhooks import get_webhook_manager, WebhookEvent
from ..utils.monitoring import get_health_checker

logger = logging.getLogger("shieldeye.api")

if not FASTAPI_AVAILABLE:
    logger.warning("FastAPI not installed. API server not available. Install with: pip install fastapi uvicorn")

class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to scan")
    standards: List[str] = Field(default=[], description="Compliance standards")
    mode: str = Field(default="Quick/Safe", description="Scan mode")
    max_pages: Optional[int] = Field(None, description="Maximum pages to scan")
    max_depth: Optional[int] = Field(None, description="Maximum crawl depth")
    timeout: int = Field(default=10, description="Request timeout")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    template: Optional[str] = Field(None, description="Template name to use")

class ScanResponse(BaseModel):
    scan_id: str
    url: str
    status: str
    message: str

class ScanResult(BaseModel):
    scan_id: str
    url: str
    mode: str
    standards: List[str]
    score: int
    status: str
    start_time: str
    end_time: Optional[str]
    duration: Optional[float]
    findings_count: Dict[str, int]

class UserCreate(BaseModel):
    username: str
    password: str
    roles: List[str] = Field(default=["viewer"])
    max_scans_per_day: int = Field(default=100)

class APIKeyCreate(BaseModel):
    name: str
    permissions: List[str]
    expires_days: Optional[int] = None
    rate_limit: int = Field(default=1000)

class ScheduleCreate(BaseModel):
    schedule_id: str
    url: str
    standards: List[str]
    mode: str
    frequency: str
    enabled: bool = True

class WebhookSubscribe(BaseModel):
    event: str
    url: str

if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="ShieldEye ComplianceScan API",
        description="Production-grade security compliance scanning API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    security = HTTPBearer()
    
    @app.middleware("http")
    async def enforce_allowed_hosts(request: Request, call_next):
        config = get_config()
        allowed_hosts = getattr(config.security, "allowed_hosts", None) or []
        if allowed_hosts and "*" not in allowed_hosts:
            host_header = request.headers.get("host", "")
            host_name = host_header.split(":", 1)[0]
            if host_name not in allowed_hosts:
                return JSONResponse(status_code=400, content={"detail": "Invalid host header"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
    
    def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
        auth = get_auth_manager()
        try:
            api_key = auth.validate_api_key(credentials.credentials)
            user = auth.users.get(api_key.username)
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            return user
        except AuthenticationError as e:
            raise HTTPException(status_code=401, detail=str(e))
    
    def require_permission(permission: str):
        def check_permission(user = Depends(get_current_user)):
            auth = get_auth_manager()
            try:
                auth.require_permission(user, permission)
                return user
            except AuthorizationError as e:
                raise HTTPException(status_code=403, detail=str(e))
        return check_permission
    
    @app.get("/")
    async def root():
        return {
            "name": "ShieldEye ComplianceScan API",
            "version": "1.0.0",
            "status": "operational",
            "docs": "/docs"
        }
    
    @app.get("/health")
    async def health_check():
        checker = get_health_checker()
        health = checker.perform_health_check()
        
        return {
            "status": health.status,
            "healthy": health.healthy,
            "checks": health.checks,
            "metrics": health.metrics,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @app.post("/scans", response_model=ScanResponse)
    async def create_scan(
        request: ScanRequest,
        background_tasks: BackgroundTasks,
        user = Depends(require_permission("scan:write"))
    ):
        config = get_config()
        db = ScanDatabase(config.database.db_path)
        
        if request.template:
            template_mgr = get_template_manager()
            template = template_mgr.get_template(request.template)
            if not template:
                raise HTTPException(status_code=404, detail=f"Template not found: {request.template}")
            
            request.standards = template.standards
            request.mode = template.mode
            request.max_pages = template.max_pages
            request.max_depth = template.max_depth
            request.timeout = template.timeout
            request.verify_ssl = template.verify_ssl
        
        try:
            def run_scan_task():
                try:
                    results = run_scan(
                        request.url,
                        request.standards,
                        request.mode,
                        max_pages=request.max_pages,
                        max_depth=request.max_depth,
                        timeout=request.timeout,
                        verify_ssl=request.verify_ssl
                    )
                    
                    analysis = analyze_scan_results(results)
                    scan_id = results.get("scan_id", "unknown")
                    
                    db.update_scan(
                        scan_id,
                        status="completed",
                        score=analysis.score,
                        counts=analysis.summary_counts,
                        results=results
                    )
                    
                    webhooks = get_webhook_manager()
                    webhooks.trigger(
                        WebhookEvent.SCAN_COMPLETED,
                        scan_id,
                        request.url,
                        {"score": analysis.score}
                    )
                    
                except Exception as e:
                    logger.error(f"Scan failed: {e}")
                    if 'scan_id' in locals():
                        db.update_scan(scan_id, status="failed", error_message=str(e))
            
            from ..core.scanner import Scanner
            scan_id = Scanner.generate_scan_id()
            db.create_scan(scan_id, request.url, request.mode, request.standards)
            
            background_tasks.add_task(run_scan_task)
            
            return ScanResponse(
                scan_id=scan_id,
                url=request.url,
                status="running",
                message="Scan started successfully"
            )
            
        except Exception as e:
            logger.exception("Failed to create scan")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/scans", response_model=List[ScanResult])
    async def list_scans(
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0),
        url: Optional[str] = None,
        status: Optional[str] = None,
        user = Depends(require_permission("scan:read"))
    ):
        config = get_config()
        db = ScanDatabase(config.database.db_path)
        
        scans = db.get_scans(limit=limit, offset=offset, url=url, status=status)
        
        return [
            ScanResult(
                scan_id=scan["scan_id"],
                url=scan["url"],
                mode=scan["mode"],
                standards=scan["standards"].split(",") if scan["standards"] else [],
                score=scan["score"] or 0,
                status=scan["status"],
                start_time=scan["start_time"],
                end_time=scan["end_time"],
                duration=scan["duration"],
                findings_count={
                    "critical": scan["critical_count"],
                    "high": scan["high_count"],
                    "medium": scan["medium_count"],
                    "low": scan["low_count"]
                }
            )
            for scan in scans
        ]
    
    @app.get("/scans/{scan_id}")
    async def get_scan(
        scan_id: str,
        user = Depends(require_permission("scan:read"))
    ):
        config = get_config()
        db = ScanDatabase(config.database.db_path)
        
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        findings = db.get_findings(scan_id)
        
        return {
            "scan": scan,
            "findings": findings
        }
    
    @app.delete("/scans/{scan_id}")
    async def delete_scan(
        scan_id: str,
        user = Depends(require_permission("scan:delete"))
    ):
        config = get_config()
        db = ScanDatabase(config.database.db_path)
        
        if not db.delete_scan(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {"message": "Scan deleted successfully"}
    
    @app.get("/scans/{scan_id}/export")
    async def export_scan_result(
        scan_id: str,
        format: str = Query("json", regex="^(json|csv|xml|sarif|markdown)$"),
        user = Depends(require_permission("scan:read"))
    ):
        config = get_config()
        db = ScanDatabase(config.database.db_path)
        
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        import json as json_lib
        import tempfile
        results = json_lib.loads(scan["results_json"])
        analysis = analyze_scan_results(results)
        
        temp_dir = Path(tempfile.gettempdir()) / "shieldeye_exports"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        safe_scan_id = "".join(c for c in scan_id if c.isalnum() or c in "-_")
        output_path = temp_dir / f"scan_{safe_scan_id}.{format}"
        export_scan(results, analysis, output_path, format)
        
        return FileResponse(
            output_path,
            media_type="application/octet-stream",
            filename=f"scan_{scan_id}.{format}"
        )
    
    @app.get("/templates")
    async def list_templates(
        tags: Optional[List[str]] = Query(None),
        user = Depends(get_current_user)
    ):
        template_mgr = get_template_manager()
        templates = template_mgr.list_templates(tags=tags)
        
        return [
            {
                "name": t.name,
                "description": t.description,
                "standards": t.standards,
                "mode": t.mode,
                "tags": t.tags
            }
            for t in templates
        ]
    
    @app.get("/templates/{name}")
    async def get_template(
        name: str,
        user = Depends(get_current_user)
    ):
        template_mgr = get_template_manager()
        template = template_mgr.get_template(name)
        
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        
        return template.to_dict()
    
    @app.post("/schedules")
    async def create_schedule(
        schedule: ScheduleCreate,
        user = Depends(require_permission("scan:write"))
    ):
        scheduler = get_scheduler()
        
        try:
            frequency = ScheduleFrequency[schedule.frequency.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid frequency: {schedule.frequency}")
        
        scheduler.add_schedule(
            schedule.schedule_id,
            schedule.url,
            schedule.standards,
            schedule.mode,
            frequency,
            enabled=schedule.enabled
        )
        
        return {"message": "Schedule created successfully"}
    
    @app.get("/schedules")
    async def list_schedules(user = Depends(require_permission("scan:read"))):
        scheduler = get_scheduler()
        schedules = scheduler.list_schedules()
        
        return [
            {
                "id": s.id,
                "url": s.url,
                "standards": s.standards,
                "mode": s.mode,
                "frequency": s.frequency.name,
                "enabled": s.enabled,
                "next_run": s.next_run.isoformat() if s.next_run else None
            }
            for s in schedules
        ]
    
    @app.delete("/schedules/{schedule_id}")
    async def delete_schedule(
        schedule_id: str,
        user = Depends(require_permission("scan:write"))
    ):
        scheduler = get_scheduler()
        
        if not scheduler.remove_schedule(schedule_id):
            raise HTTPException(status_code=404, detail="Schedule not found")
        
        return {"message": "Schedule deleted successfully"}
    
    @app.post("/webhooks/subscribe")
    async def subscribe_webhook(
        subscription: WebhookSubscribe,
        user = Depends(require_permission("config:write"))
    ):
        webhooks = get_webhook_manager()
        
        try:
            event = WebhookEvent[subscription.event.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid event: {subscription.event}")
        
        webhooks.subscribe(event, subscription.url)
        
        return {"message": "Webhook subscribed successfully"}
    
    @app.get("/webhooks")
    async def list_webhooks(user = Depends(require_permission("config:write"))):
        webhooks = get_webhook_manager()
        
        return {
            event.name: urls
            for event, urls in webhooks.subscriptions.items()
        }
    
    @app.post("/users")
    async def create_user(
        user_data: UserCreate,
        user = Depends(require_permission("user:manage"))
    ):
        auth = get_auth_manager()
        
        try:
            new_user = auth.create_user(
                user_data.username,
                user_data.password,
                user_data.roles,
                user_data.max_scans_per_day
            )
            return {"message": f"User {new_user.username} created successfully"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @app.post("/api-keys")
    async def create_api_key(
        key_data: APIKeyCreate,
        user = Depends(get_current_user)
    ):
        auth = get_auth_manager()
        
        api_key = auth.create_api_key(
            user.username,
            key_data.name,
            key_data.permissions,
            key_data.expires_days,
            key_data.rate_limit
        )
        
        return {
            "message": "API key created successfully",
            "key": api_key.key,
            "warning": "Save this key securely. It won't be shown again."
        }
    
    @app.get("/stats")
    async def get_statistics(user = Depends(require_permission("scan:read"))):
        config = get_config()
        db = ScanDatabase(config.database.db_path)
        
        return db.get_statistics()

def start_api_server(host: str = "0.0.0.0", port: int = 8000):
    if not FASTAPI_AVAILABLE:
        print("ERROR: FastAPI not installed. Install with: pip install fastapi uvicorn")
        return
    
    try:
        import uvicorn
        uvicorn.run(app, host=host, port=port)
    except ImportError:
        print("ERROR: uvicorn not installed. Install with: pip install uvicorn")

if __name__ == "__main__":
    start_api_server()
