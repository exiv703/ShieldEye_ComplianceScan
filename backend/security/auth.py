from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import json
import logging

from ..core.exceptions import ShieldEyeError

logger = logging.getLogger("shieldeye.auth")

class AuthenticationError(ShieldEyeError):
    pass

class AuthorizationError(ShieldEyeError):
    pass

@dataclass
class User:
    username: str
    password_hash: str
    roles: List[str] = field(default_factory=list)
    api_keys: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_login: Optional[str] = None
    enabled: bool = True
    max_scans_per_day: int = 100
    allowed_standards: List[str] = field(default_factory=lambda: ["GDPR", "PCI-DSS", "ISO 27001"])

@dataclass
class Session:
    session_id: str
    username: str
    created_at: float
    expires_at: float
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

@dataclass
class APIKey:
    key: str
    username: str
    name: str
    created_at: str
    last_used: Optional[str] = None
    expires_at: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    rate_limit: int = 1000

class AuthManager:
    
    ROLES = {
        "admin": ["scan:read", "scan:write", "scan:delete", "user:manage", "config:write"],
        "analyst": ["scan:read", "scan:write", "report:generate"],
        "viewer": ["scan:read", "report:view"],
        "api": ["scan:read", "scan:write"],
    }
    
    def __init__(self, users_file: Optional[Path] = None):
        self.users_file = users_file or Path.home() / ".shieldeye" / "users.json"
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self._load_users()
    
    def _load_users(self) -> None:
        if not self.users_file.exists():
            self.users_file.parent.mkdir(parents=True, exist_ok=True)
            initial_password = os.environ.get("SHIELDEYE_INITIAL_ADMIN_PASSWORD")
            if initial_password:
                password_source = "environment variable SHIELDEYE_INITIAL_ADMIN_PASSWORD"
            else:
                initial_password = secrets.token_urlsafe(20)
                password_source = "securely generated random password"

            default_admin = self.create_user(
                "admin",
                initial_password,
                ["admin"],
                max_scans_per_day=1000,
            )
            logger.warning(
                "Created default admin user 'admin' with password from %s. "
                "Change this password immediately after first login.",
                password_source,
            )
            self._save_users()
            return
        
        try:
            with open(self.users_file, "r") as f:
                data = json.load(f)
                for username, user_data in data.get("users", {}).items():
                    self.users[username] = User(**user_data)
                for key, key_data in data.get("api_keys", {}).items():
                    self.api_keys[key] = APIKey(**key_data)
            logger.info(f"Loaded {len(self.users)} users")
        except Exception as e:
            logger.error(f"Failed to load users: {e}")
    
    def _save_users(self) -> None:
        try:
            data = {
                "users": {u: vars(user) for u, user in self.users.items()},
                "api_keys": {k: vars(key) for k, key in self.api_keys.items()}
            }
            with open(self.users_file, "w") as f:
                json.dump(data, f, indent=2)
            try:
                self.users_file.chmod(0o600)
            except Exception:
                logger.warning("Failed to set restrictive permissions on users file: %s", self.users_file)
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
    
    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${pwd_hash.hex()}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        try:
            salt, pwd_hash = password_hash.split('$')
            new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return new_hash.hex() == pwd_hash
        except Exception:
            return False
    
    @staticmethod
    def validate_password_strength(password: str) -> None:
        if len(password) < 12:
            raise AuthenticationError("Password must be at least 12 characters long")
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            raise AuthenticationError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
    
    def create_user(
        self,
        username: str,
        password: str,
        roles: List[str],
        max_scans_per_day: int = 100,
        allowed_standards: Optional[List[str]] = None
    ) -> User:
        if username in self.users:
            raise AuthenticationError(f"User {username} already exists")
        self.validate_password_strength(password)
        
        user = User(
            username=username,
            password_hash=self.hash_password(password),
            roles=roles,
            max_scans_per_day=max_scans_per_day,
            allowed_standards=allowed_standards or ["GDPR", "PCI-DSS", "ISO 27001"]
        )
        self.users[username] = user
        self._save_users()
        logger.info(f"Created user: {username}")
        return user
    
    def authenticate(self, username: str, password: str) -> User:
        user = self.users.get(username)
        if not user:
            raise AuthenticationError("Invalid username or password")
        
        if not user.enabled:
            raise AuthenticationError("User account is disabled")
        
        if not self.verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid username or password")
        
        user.last_login = datetime.utcnow().isoformat()
        self._save_users()
        logger.info(f"User authenticated: {username}")
        return user
    
    def create_session(
        self,
        username: str,
        duration_hours: int = 24,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Session:
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        
        session = Session(
            session_id=session_id,
            username=username,
            created_at=now,
            expires_at=now + (duration_hours * 3600),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.sessions[session_id] = session
        logger.info(f"Created session for {username}")
        return session
    
    def validate_session(self, session_id: str) -> User:
        session = self.sessions.get(session_id)
        if not session:
            raise AuthenticationError("Invalid session")
        
        if time.time() > session.expires_at:
            del self.sessions[session_id]
            raise AuthenticationError("Session expired")
        
        user = self.users.get(session.username)
        if not user or not user.enabled:
            raise AuthenticationError("User not found or disabled")
        
        return user
    
    def create_api_key(
        self,
        username: str,
        name: str,
        permissions: List[str],
        expires_days: Optional[int] = None,
        rate_limit: int = 1000
    ) -> APIKey:
        if username not in self.users:
            raise AuthenticationError(f"User {username} not found")
        
        key = f"sk_{secrets.token_urlsafe(32)}"
        expires_at = None
        if expires_days:
            expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()
        
        api_key = APIKey(
            key=key,
            username=username,
            name=name,
            created_at=datetime.utcnow().isoformat(),
            expires_at=expires_at,
            permissions=permissions,
            rate_limit=rate_limit
        )
        
        self.api_keys[key] = api_key
        user = self.users[username]
        user.api_keys.append(key)
        self._save_users()
        
        logger.info(f"Created API key '{name}' for {username}")
        return api_key
    
    def validate_api_key(self, key: str) -> APIKey:
        api_key = self.api_keys.get(key)
        if not api_key:
            raise AuthenticationError("Invalid API key")
        
        if api_key.expires_at:
            expires = datetime.fromisoformat(api_key.expires_at)
            if datetime.utcnow() > expires:
                raise AuthenticationError("API key expired")
        
        user = self.users.get(api_key.username)
        if not user or not user.enabled:
            raise AuthenticationError("User not found or disabled")
        
        api_key.last_used = datetime.utcnow().isoformat()
        self._save_users()
        
        return api_key
    
    def check_permission(self, user: User, permission: str) -> bool:
        for role in user.roles:
            role_perms = self.ROLES.get(role, [])
            if permission in role_perms or "*" in role_perms:
                return True
        return False
    
    def require_permission(self, user: User, permission: str) -> None:
        if not self.check_permission(user, permission):
            raise AuthorizationError(
                f"Permission denied: {permission}",
                details={"user": user.username, "permission": permission}
            )
    
    def revoke_api_key(self, key: str) -> None:
        if key in self.api_keys:
            api_key = self.api_keys[key]
            user = self.users.get(api_key.username)
            if user and key in user.api_keys:
                user.api_keys.remove(key)
            del self.api_keys[key]
            self._save_users()
            logger.info(f"Revoked API key: {api_key.name}")
    
    def list_users(self) -> List[User]:
        return list(self.users.values())
    
    def delete_user(self, username: str) -> None:
        if username not in self.users:
            raise AuthenticationError(f"User {username} not found")
        
        user = self.users[username]
        for key in list(user.api_keys):
            if key in self.api_keys:
                del self.api_keys[key]
        
        del self.users[username]
        self._save_users()
        logger.info(f"Deleted user: {username}")

_auth_manager: Optional[AuthManager] = None

def get_auth_manager() -> AuthManager:
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager
