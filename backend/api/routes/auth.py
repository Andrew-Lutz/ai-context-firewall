"""
Authentication Routes.

JWT-based authentication with:
- Login with email/password
- Token refresh
- Logout (token invalidation via Redis blacklist)
- Current user info
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

from config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()
router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    role: str
    tenant_id: str
    department: Optional[str]


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# JWT Utilities
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(data: dict) -> str:
    """Create a signed JWT refresh token with longer expiry."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_token(token: str, expected_type: str = "access") -> dict:
    """
    Decode and validate a JWT token.
    Raises HTTPException 401 on any validation failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("type") != expected_type:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify bcrypt-hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return pwd_context.hash(password)



# ---------------------------------------------------------------------------
# Demo users (module-level for shared access)
# ---------------------------------------------------------------------------

_DEMO_USERS_RAW = {
    "admin@demo.com": {"password": "admin123", "role": "admin", "tenant_id": "tenant_acme_corp"},
    "admin@firewall.local": {"password": "ChangeMe123!", "role": "super_admin", "tenant_id": "default"},
    "analyst@firewall.local": {"password": "ChangeMe123!", "role": "security_analyst", "tenant_id": "default"},
    "analyst@demo.com": {"password": "analyst123", "role": "analyst", "tenant_id": "tenant_acme_corp"},
    "user@demo.com": {"password": "user123", "role": "employee", "tenant_id": "tenant_acme_corp"},
}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT tokens",
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """
    Authenticate user with email/password.
    Returns access token (short-lived) and refresh token (long-lived).
    """
    # TODO: Replace with real DB user lookup
    # user = await get_user_by_email(form_data.username)
    # if not user or not verify_password(form_data.password, user.hashed_password):
    #     raise HTTPException(status_code=401, detail="Invalid credentials")

    # Demo authentication (remove in production)
    DEMO_USERS = {
        "admin@firewall.local": {
            "id": "00000000-0000-0000-0000-000000000001",
            "hashed_password": hash_password("ChangeMe123!"),
            "role": "super_admin",
            "tenant_id": "default",
            "full_name": "Platform Administrator",
            "department": "Security",
        },
        "analyst@firewall.local": {
            "id": "00000000-0000-0000-0000-000000000002",
            "hashed_password": hash_password("ChangeMe123!"),
            "role": "security_analyst",
            "tenant_id": "default",
            "full_name": "Security Analyst",
            "department": "Security",
        },
    }

    user = DEMO_USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        logger.warning("login_failed", username=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {
        "sub": user["id"],
        "email": form_data.username,
        "role": user["role"],
        "tenant_id": user["tenant_id"],
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    logger.info("login_success", user_id=user["id"], role=user["role"])

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using refresh token",
)
async def refresh_token(request: RefreshRequest) -> TokenResponse:
    """Exchange a valid refresh token for a new access token."""
    payload = verify_token(request.refresh_token, expected_type="refresh")

    token_data = {
        "sub": payload["sub"],
        "email": payload.get("email"),
        "role": payload.get("role"),
        "tenant_id": payload.get("tenant_id"),
    }

    new_access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user",
)
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserResponse:
    """Return the profile of the currently authenticated user."""
    payload = verify_token(token)
    return UserResponse(
        id=payload["sub"],
        email=payload.get("email", ""),
        full_name=payload.get("full_name"),
        role=payload.get("role", "developer"),
        tenant_id=payload.get("tenant_id", "default"),
        department=payload.get("department"),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout and invalidate token",
)
async def logout(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Invalidate the current token by adding to Redis blacklist.
    Client must discard both access and refresh tokens.
    """
    payload = verify_token(token)
    # TODO: Add token to Redis blacklist
    # await redis.setex(f"blacklist:{token}", ttl, "1")
    logger.info("logout_success", user_id=payload.get("sub"))
    return {"status": "logged_out"}


# ---------------------------------------------------------------------------
# JSON login convenience endpoint (for API clients)
# ---------------------------------------------------------------------------

class LoginJsonRequest(BaseModel):
    email:    str
    password: str


@router.post("/login/json", response_model=TokenResponse, summary="JSON login")
async def login_json(req: LoginJsonRequest) -> TokenResponse:
    """JSON body login — for API clients that don't use OAuth2 form encoding."""
    user = _DEMO_USERS_RAW.get(req.email)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token  = create_access_token({"sub": req.email, "role": user["role"], "tenant_id": user["tenant_id"]})
    refresh_token = create_refresh_token({"sub": req.email})
    return TokenResponse(
        access_token  = access_token,
        refresh_token = refresh_token,
        token_type    = "bearer",
        expires_in    = 3600,
        user          = {"email": req.email, "role": user["role"], "tenant_id": user["tenant_id"]},
    )
