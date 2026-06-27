from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Callable, Dict, List, Literal, cast
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from backend.security.auth import (
    AuthorizationError,
    AuthenticationError,
    get_auth_manager,
)
from policy.validator import PolicyDocument, validate_rego_stub

logger = logging.getLogger("shieldeye.api.policies")
router = APIRouter(tags=["policies"])
security = HTTPBearer()


class PolicySummary(BaseModel):  # type: ignore[misc]
    policy_id: str = Field(..., description="UUID or slug identifier")
    name: str = Field(..., description="Human-readable policy name")
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"]
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    created_at: datetime
    updated_at: datetime
    status: Literal["draft", "pending_approval", "approved", "archived"]


class PolicyDocumentCreate(BaseModel):  # type: ignore[misc]
    policy_id: str = Field(..., description="UUID or slug identifier")
    name: str = Field(..., min_length=1)
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"]
    version: str = Field(default="1.0.0", pattern=r"^\d+\.\d+\.\d+$")
    status: Literal["draft", "pending_approval", "approved", "archived"] = "draft"
    yaml_document: Dict[str, Any]
    rego_content: str | None = None


class PolicyDocumentUpdate(BaseModel):  # type: ignore[misc]
    name: str | None = None
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"] | None = None
    status: Literal["draft", "pending_approval", "approved", "archived"] | None = None
    yaml_document: Dict[str, Any] | None = None
    rego_content: str | None = None


class PolicyVersionEntry(BaseModel):  # type: ignore[misc]
    version: str
    updated_at: datetime
    updated_by: str
    status: Literal["draft", "pending_approval", "approved", "archived"]


class PolicyDetail(BaseModel):  # type: ignore[misc]
    summary: PolicySummary
    document: PolicyDocument
    rego_content: str | None = None
    version_history: List[PolicyVersionEntry]


class ApprovePolicyRequest(BaseModel):  # type: ignore[misc]
    approver: str | None = None


_POLICY_STORE: Dict[str, Dict[str, Any]] = {}


# version history doubles as the audit trail for policy changes; the approval
# step keeps unreviewed policies out of live scans


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _next_semver(version: str) -> str:
    major, minor, patch = (int(part) for part in version.split("."))
    return f"{major}.{minor}.{patch + 1}"


def _authenticate(
    credentials: Annotated[
        HTTPAuthorizationCredentials,
        Security(security),
    ],
) -> Any:
    auth = get_auth_manager()
    try:
        api_key = auth.validate_api_key(credentials.credentials)
        user = auth.users.get(api_key.username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _require_permission(permission: str) -> Callable[[Any], Any]:
    def checker(user: Annotated[Any, Depends(_authenticate)]) -> Any:
        auth = get_auth_manager()
        try:
            auth.require_permission(user, permission)
            return user
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return checker


def _policy_validation_hint(
    policy_id: str,
    payload: Dict[str, Any],
    rego_content: str | None,
    exc: Exception,
) -> str:
    message = str(exc).lower()
    if "rego content is incomplete" in message:
        return (
            "hint: include OPA keywords 'package' + ('rule' or 'default') + 'allow' "
            "before approving policy"
        )
    if "control_id" in message:
        standard = payload.get("standard", "STANDARD")
        return f"hint: control_id must match pattern {standard}-X.Y[.Z] (example: CIS-4.1.3)"
    if "field required" in message:
        return "hint: verify required YAML keys: control_id, description, check, remediation, severity"
    if rego_content:
        return "hint: verify YAML schema and Rego stub alignment for policy lifecycle validation"
    return f"hint: check YAML syntax and standard mapping for policy {policy_id}"


def _validate_payload(
    policy_id: str, payload: Dict[str, Any], rego_content: str | None
) -> PolicyDocument:
    try:
        policy_document = PolicyDocument(**payload)
        if rego_content and not validate_rego_stub(rego_content):
            raise ValueError("rego content is incomplete")
        return policy_document
    except Exception as exc:
        hint = _policy_validation_hint(policy_id, payload, rego_content, exc)
        logger.warning(
            "Policy validation failed for %s. %s",
            policy_id,
            hint,
        )
        raise HTTPException(status_code=422, detail=f"{exc}. {hint}") from exc


@router.get("/policies", response_model=List[PolicySummary])  # type: ignore[misc]
async def list_policies(
    user: Annotated[Any, Depends(_require_permission("scan:read"))],
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"] | None = Query(default=None),
    status: Literal["draft", "pending_approval", "approved", "archived"] | None = Query(
        default=None
    ),
) -> List[PolicySummary]:
    _ = user
    summaries: List[PolicySummary] = []
    for entry in _POLICY_STORE.values():
        summary = PolicySummary.model_validate(entry["summary"])
        if standard and summary.standard != standard:
            continue
        if status and summary.status != status:
            continue
        summaries.append(summary)
    return summaries


@router.get("/policies/{policy_id}", response_model=PolicyDetail)  # type: ignore[misc]
async def get_policy(
    policy_id: str,
    user: Annotated[Any, Depends(_require_permission("scan:read"))],
) -> PolicyDetail:
    _ = user
    stored = _POLICY_STORE.get(policy_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    return PolicyDetail(
        summary=PolicySummary.model_validate(stored["summary"]),
        document=PolicyDocument.model_validate(stored["document"]),
        rego_content=stored.get("rego_content"),
        version_history=[
            PolicyVersionEntry.model_validate(item)
            for item in stored["version_history"]
        ],
    )


@router.post("/policies", response_model=PolicyDetail, status_code=201)  # type: ignore[misc]
async def create_policy(
    request: PolicyDocumentCreate,
    user: Annotated[Any, Depends(_require_permission("scan:write"))],
) -> PolicyDetail:
    if request.policy_id in _POLICY_STORE:
        raise HTTPException(status_code=409, detail="Policy already exists")

    payload = dict(request.yaml_document)
    payload["standard"] = request.standard
    document = _validate_payload(request.policy_id, payload, request.rego_content)

    now = _utcnow()
    summary = PolicySummary(
        policy_id=request.policy_id,
        name=request.name,
        standard=request.standard,
        version=request.version,
        created_at=now,
        updated_at=now,
        status=request.status,
    )
    version_history = [
        PolicyVersionEntry(
            version=request.version,
            updated_at=now,
            updated_by=getattr(user, "username", "unknown"),
            status=request.status,
        )
    ]

    _POLICY_STORE[request.policy_id] = {
        "summary": summary.model_dump(),
        "document": document.model_dump(),
        "rego_content": request.rego_content,
        "version_history": [entry.model_dump() for entry in version_history],
    }

    logger.info("Policy %s created (version=%s)", request.policy_id, request.version)

    return PolicyDetail(
        summary=summary,
        document=document,
        rego_content=request.rego_content,
        version_history=version_history,
    )


@router.put("/policies/{policy_id}", response_model=PolicyDetail)  # type: ignore[misc]
async def update_policy(
    policy_id: str,
    request: PolicyDocumentUpdate,
    user: Annotated[Any, Depends(_require_permission("scan:write"))],
) -> PolicyDetail:
    stored = _POLICY_STORE.get(policy_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    current_summary = PolicySummary.model_validate(stored["summary"])
    new_standard = request.standard or current_summary.standard
    yaml_payload = dict(stored["document"])
    if request.yaml_document is not None:
        yaml_payload.update(request.yaml_document)
    yaml_payload["standard"] = new_standard

    rego_content = (
        request.rego_content
        if request.rego_content is not None
        else stored.get("rego_content")
    )
    updated_document = _validate_payload(policy_id, yaml_payload, rego_content)

    now = _utcnow()
    next_version = _next_semver(current_summary.version)
    updated_summary = PolicySummary(
        policy_id=policy_id,
        name=request.name or current_summary.name,
        standard=new_standard,
        version=next_version,
        created_at=current_summary.created_at,
        updated_at=now,
        status=request.status or current_summary.status,
    )

    history = [
        PolicyVersionEntry.model_validate(item) for item in stored["version_history"]
    ]
    history.append(
        PolicyVersionEntry(
            version=next_version,
            updated_at=now,
            updated_by=getattr(user, "username", "unknown"),
            status=updated_summary.status,
        )
    )

    _POLICY_STORE[policy_id] = {
        "summary": updated_summary.model_dump(),
        "document": updated_document.model_dump(),
        "rego_content": rego_content,
        "version_history": [entry.model_dump() for entry in history],
    }

    return PolicyDetail(
        summary=updated_summary,
        document=updated_document,
        rego_content=rego_content,
        version_history=history,
    )


@router.post("/policies/{policy_id}/approve", response_model=PolicySummary)  # type: ignore[misc]
async def approve_policy(
    policy_id: str,
    request: ApprovePolicyRequest,
    user: Annotated[Any, Depends(_require_permission("config:write"))],
) -> PolicySummary:
    stored = _POLICY_STORE.get(policy_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    now = _utcnow()
    summary = PolicySummary.model_validate(stored["summary"])
    approved_summary = summary.model_copy(
        update={
            "status": "approved",
            "updated_at": now,
        }
    )

    history = [
        PolicyVersionEntry.model_validate(item) for item in stored["version_history"]
    ]
    history.append(
        PolicyVersionEntry(
            version=approved_summary.version,
            updated_at=now,
            updated_by=request.approver or getattr(user, "username", "unknown"),
            status="approved",
        )
    )

    stored["summary"] = approved_summary.model_dump()
    stored["version_history"] = [entry.model_dump() for entry in history]

    return cast(PolicySummary, approved_summary)


@router.delete("/policies/{policy_id}", response_model=PolicySummary)  # type: ignore[misc]
async def archive_policy(
    policy_id: str,
    user: Annotated[Any, Depends(_require_permission("scan:delete"))],
) -> PolicySummary:
    stored = _POLICY_STORE.get(policy_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    now = _utcnow()
    summary = PolicySummary.model_validate(stored["summary"])
    archived = summary.model_copy(update={"status": "archived", "updated_at": now})

    history = [
        PolicyVersionEntry.model_validate(item) for item in stored["version_history"]
    ]
    history.append(
        PolicyVersionEntry(
            version=archived.version,
            updated_at=now,
            updated_by=getattr(user, "username", "unknown"),
            status="archived",
        )
    )

    stored["summary"] = archived.model_dump()
    stored["version_history"] = [entry.model_dump() for entry in history]

    return cast(PolicySummary, archived)

