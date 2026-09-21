# ============================================================================
# BOXY VEHICLE API -- single-file FastAPI app.
#
# Rough map of what's below, top to bottom:
#   1. Imports
#   2. App lifespan (InfluxDB client)
#   3. Config (env vars, constants)
#   4. Login lockout / rate-limit state (in-memory)
#   5. InfluxDB query config
#   6. Security utilities setup (password hashing, OAuth2, limiter)
#   7. Telemetry query helpers
#   8. Database session dependency
#   9. Password hashing helpers
#  10. Login lockout helpers (cont'd -- see #4)
#  11. JWT token creation
#  12. DB lookup helpers (sync, run via threadpool)
#  12b. (unused) Influx result helper, sits between #11 and #12 in the file
#  13. Auth dependencies (JWT validation -> current user)
#  14. FastAPI app instance
#  15. Global exception handlers
#  16. Routes: auth (login / refresh)
#  17. Routes: users (self-service)
#  18. Routes: telemetry
#  19. Routes: admin -- users
#  20. Routes: admin -- vehicles


import json
import os
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from influxdb_client.client.influxdb_client_async import InfluxDBClientAsync
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from contextlib import asynccontextmanager
 
from database import UserDB, VehicleDB, SessionLocal

# Request/response models (Pydantic) live in schemas.py, not here —
# keeps validation rules separate from endpoint logic.
from schemas import (
    Token,
    TokenData,
    User,
    VehicleOut,
    AdminUserCreate,
    AdminUserUpdate,
    AdminVehicleCreate,
    AdminVehicleUpdate,
    RefreshRequest,
)
 
load_dotenv()
 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s'
)
logger = logging.getLogger(__name__)
 
# ==============================================================================
# 2. APP LIFESPAN -- InfluxDB async client
# Opens one InfluxDB client for the app's lifetime, closes it on shutdown.
# ==============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    t0 = time.perf_counter()
    client = InfluxDBClientAsync(url=url, token=token, org=org)
    app.state.influx_client = client
    app.state.query_api = client.query_api()
    logger.info(f"InfluxDB client initialized in {time.perf_counter() - t0:.4f}s")
    yield
    await client.close()
    logger.info("InfluxDB client closed")
 
# ==============================================================================
# 3. CONFIG -- environment variables & constants
# Everything the app needs at startup: secrets, InfluxDB coordinates, token lifetimes.
# ==============================================================================
def require_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value
 
JWT_SECRET_KEY = require_env("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

# ==============================================================================
# 4. LOGIN LOCKOUT / RATE-LIMIT STATE (in-memory)
# Per-account soft rate limit (3/min) + hard lockout (5 strikes -> 15min), plus
# the "phantom" mirror of both for usernames that don't exist (timing-attack fix).
# See authenticate_user() further down for how these get combined.
# ==============================================================================
# Per-account rate limit, separate from the per-IP one (slowapi, on the
# route itself). This one is keyed by the *username being attempted*, so
# it also catches an attacker spreading login attempts for one account
# across many different IPs to dodge the per-IP limit. It's intentionally
# a short, "soft" window on top of the longer, "hard" lockout above.
#
# In-memory only (per API process) -- fine for a single container. If this
# API ever runs as multiple replicas, this would need to move to something
# shared (e.g. a Redis counter) to stay effective across all of them.
ACCOUNT_RATE_LIMIT_WINDOW_SECONDS = 60
ACCOUNT_RATE_LIMIT_MAX_ATTEMPTS = 3
_recent_attempts_by_username: dict[str, deque] = defaultdict(deque)

# Mirrors the DB-backed failed_login_attempts/locked_until, but in memory,
# for usernames that don't exist. Without this, a nonexistent username can
# never reach 423 (there's no DB row to lock) while a real one eventually
# does -- and that difference alone reveals which usernames are real,
# regardless of how careful we are about response timing. Same 5-strikes /
# 15-minute shape as the real thing, just stored differently.
_phantom_fail_counts: dict[str, int] = defaultdict(int)
_phantom_locked_until: dict[str, datetime] = {}


def _is_account_rate_limited(username: str) -> bool:
    """
    True if this exact username has already failed to log in
    ACCOUNT_RATE_LIMIT_MAX_ATTEMPTS times in the last
    ACCOUNT_RATE_LIMIT_WINDOW_SECONDS -- regardless of which IP(s) the
    attempts came from. Checked against the submitted username string
    itself (not a DB lookup), so it behaves identically whether or not
    the account actually exists -- consistent with the timing-attack fix.
    """
    now = time.time()
    attempts = _recent_attempts_by_username[username]
    while attempts and now - attempts[0] > ACCOUNT_RATE_LIMIT_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts) >= ACCOUNT_RATE_LIMIT_MAX_ATTEMPTS


def _record_failed_attempt(username: str):
    _recent_attempts_by_username[username].append(time.time())
 
# ==============================================================================
# 5. INFLUXDB QUERY CONFIG
# Bucket/org/url/token for the telemetry queries in the /api/data route.
# ==============================================================================
bucket = require_env("INFLUX_BUCKET")
org = require_env("INFLUX_ORG")
url = require_env("INFLUX_URL")
token = require_env("INFLUX_TOKEN")
measurement = "mqtt_consumer"
 
 
# ==============================================================================
# 6. SECURITY UTILITIES SETUP
# Password hasher, OAuth2 bearer scheme, and the per-IP slowapi rate limiter.
# ==============================================================================
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
limiter = Limiter(key_func=get_remote_address)
 
# Fields actually written by seed_data.py / the vehicle telemetry pipeline
ALLOWED_FIELDS = {"speed", "soc", "battery_temp"}
 
 
# ==============================================================================
# 7. TELEMETRY QUERY HELPERS
# Small validators used by the /api/data route.
# ==============================================================================
def validate_time_range(start_time: int, stop_time: int):
    if start_time >= stop_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must be less than stop_time",
        )
 
# ==============================================================================
# 8. DATABASE SESSION DEPENDENCY
# Standard FastAPI "yield a session, close it after the request" pattern.
# ==============================================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
 
# ==============================================================================
# 9. PASSWORD HASHING HELPERS
# Wraps pwdlib. _DUMMY_HASH below exists purely to equalize timing for logins
# against usernames that don't exist (see Counter Timing Attacks task).
# ==============================================================================
def verify_password(plain_password, hashed_password):
    t0 = time.perf_counter()
    result = password_hash.verify(plain_password, hashed_password)
    logger.info(f"Password verification executed in {time.perf_counter() - t0:.4f}s")
    return result

def get_password_hash(password):
    return password_hash.hash(password)

# A real hash of a throwaway value, computed once at import time. Used as a
# stand-in when the username doesn't exist, so a nonexistent-username login
# still pays the same hashing cost as a real one -- otherwise the response
# comes back measurably faster for unknown usernames, which is itself a leak
# (see: Counter Timing Attacks).
_DUMMY_HASH = password_hash.hash("not-a-real-password-just-for-timing")


# ==============================================================================
# 10. LOGIN LOCKOUT HELPERS (cont'd -- state declared earlier in this file, see #4)
# _bump_failed_attempts / _is_locked / authenticate_user are one unit: this is
# the actual login flow that enforces the lockout state from section 4.
# ==============================================================================
def _bump_failed_attempts(db: Session, user: "UserDB | None", username: str) -> bool:
    """
    Advance the hard-lockout counter -- for a real user, in the DB; for a
    username that doesn't exist, in the in-memory phantom store, so both
    cases lock out after the same number of strikes and for the same
    duration. Called on every failed attempt, whether it was rejected by
    the soft per-minute rate limit or by an actually-wrong password.
    Returns True if this call just caused a lockout to start.
    """
    if user is None:
        _phantom_fail_counts[username] += 1
        if _phantom_fail_counts[username] >= MAX_FAILED_LOGIN_ATTEMPTS:
            _phantom_locked_until[username] = datetime.now(timezone.utc) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
            _phantom_fail_counts[username] = 0
            return True
        return False

    user.failed_login_attempts += 1
    just_locked = False
    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        user.failed_login_attempts = 0
        just_locked = True
    db.commit()
    return just_locked


def _is_locked(locked_until: datetime | None) -> bool:
    """
    True if locked_until is set and still in the future. Normalizes to UTC
    first: some DB backends (SQLite, notably -- used in tests) don't
    round-trip timezone-aware datetimes the way Postgres does, so a value
    read back can come out naive even though it was stored as UTC-aware.
    """
    if locked_until is None:
        return False
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def authenticate_user(db: Session, username: str, password: str) -> UserDB:
    """
    Verifies credentials and enforces per-account lockout after repeated
    failures. Raises HTTPException directly (423 if locked, 429 if rate
    limited, 401 if the credentials are wrong) instead of returning False,
    so the caller doesn't need its own branch for "why did this fail".
    """
    user = db.query(UserDB).filter(UserDB.username == username).first()

    # Already locked out -- for a real user, that's in the DB; for a
    # nonexistent username, it's in the phantom store. Same response either
    # way, so the two cases can't be told apart from the outside.
    real_lock = user and _is_locked(user.locked_until)
    phantom_lock_until = _phantom_locked_until.get(username)
    phantom_lock = user is None and _is_locked(phantom_lock_until)
    if real_lock or phantom_lock:
        locked_until = user.locked_until if real_lock else phantom_lock_until
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked due to repeated failed logins. Try again after {locked_until.isoformat()}.",
        )

    # Per-account burst limit (independent of the per-IP one on the route,
    # and independent of whether this username actually exists). A burst
    # that trips this still counts toward the hard lockout below, so
    # spamming attempts doesn't "pause" progress toward being locked out.
    if _is_account_rate_limited(username):
        _record_failed_attempt(username)
        just_locked = _bump_failed_attempts(db, user, username)
        if just_locked:
            locked_until = user.locked_until if user else _phantom_locked_until[username]
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account locked due to repeated failed logins. Try again after {locked_until.isoformat()}.",
            )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts for this account. Wait a minute and try again.",
        )

    password_ok = verify_password(password, user.hashed_password if user else _DUMMY_HASH)

    if not user or not password_ok:
        _record_failed_attempt(username)
        just_locked = _bump_failed_attempts(db, user, username)
        if just_locked:
            locked_until = user.locked_until if user else _phantom_locked_until[username]
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account locked due to repeated failed logins. Try again after {locked_until.isoformat()}.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Successful login -- clear any prior failures/lock.
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    return user

# ==============================================================================
# 11. JWT TOKEN CREATION
# Access tokens (short-lived, for calling the API) and refresh tokens (long-lived,
# only valid at /token/refresh). Both carry "ver" = token_version for revocation.
# ==============================================================================
def create_access_token(username: str, token_version: int, expires_delta: timedelta | None = None):
    """A short-lived token used to call the API. Carries 'type': 'access'."""
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {"sub": username, "ver": token_version, "type": "access", "exp": expire}
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(username: str, token_version: int):
    """
    A long-lived token whose only job is to get a new access token later,
    without asking for the password again. Carries 'type': 'refresh' so it
    can't be used directly against protected endpoints.
    """
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": username, "ver": token_version, "type": "refresh", "exp": expire}
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
 
# ==============================================================================
# 12b. INFLUX RESULT HELPER (currently unused -- /api/data streams records
# ==============================================================================
# directly instead; candidate for removal, kept for now)
# ==============================================================================
def parse_influx_result(tables):
    results = []
    for table in tables:
        for record in table.records:
            results.append(record.values)
    return results

# ==============================================================================
# 12. DB LOOKUP HELPERS (sync -- called via run_in_threadpool from async routes)
# ==============================================================================
def _get_user_by_username_sync(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()
 
def _get_vehicle_sync(db: Session, vehicle_id: str):
    return db.query(VehicleDB).filter(VehicleDB.vehicle_id == vehicle_id).first()
 
# ==============================================================================
# 13. AUTH DEPENDENCIES -- JWT validation chain
# get_current_user (valid token + not revoked) -> get_current_active_user (not
# disabled) -> get_current_admin_user (is_admin). Routes depend on whichever
# level of access they need.
# ==============================================================================
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    t0 = time.perf_counter()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    revoked_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token has been revoked",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        # Refresh tokens are only valid at POST /token/refresh, never here.
        if payload.get("type") == "refresh":
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
 
    t_db = time.perf_counter()
    # Run the blocking SQLAlchemy call in a threadpool so it doesn't block the event loop
    user = await run_in_threadpool(_get_user_by_username_sync, db, token_data.username)
    logger.info(f"Database query (get_current_user) executed in {time.perf_counter() - t_db:.4f}s")
 
    if user is None:
        raise credentials_exception
 
    # If the user's token_version has moved on since this token was issued
    # (logout-all, admin revoke, password reset, etc.), reject it.
    if payload.get("ver") != user.token_version:
        raise revoked_exception
 
    logger.info(f"Token validation and user retrieval executed in {time.perf_counter() - t0:.4f}s")
    return user
 
async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)],):
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user
 
async def get_current_admin_user(current_user: Annotated[UserDB, Depends(get_current_active_user)]):
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user
 
# ==============================================================================
# 14. FASTAPI APP INSTANCE
# ==============================================================================
app = FastAPI(
    lifespan=lifespan,
    title="Boxy Vehicle API",
    description="API for authenticating users and retrieving vehicle telemetry from InfluxDB. "
                 "Each vehicle belongs to exactly one user; telemetry access is restricted to the vehicle's owner.",
    version="1.0.0",
)
app.state.limiter = limiter
 
 
# ==============================================================================
# 15. GLOBAL EXCEPTION HANDLERS
# Standardizes every error response into {"error": {"status_code", "message", ...}}.
# ==============================================================================
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"status_code": exc.status_code, "message": exc.detail}},
        headers=getattr(exc, "headers", None) or {},
    )
 
 
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
                "message": "Invalid request parameters",
                "details": exc.errors(),
            }
        },
    )
 
 
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"error": {"status_code": status.HTTP_429_TOO_MANY_REQUESTS, "message": "Rate limit exceeded, please slow down"}},
    )
 
 
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": {"status_code": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": "Internal server error"}},
    )
 
 
# ==============================================================================
# 16. ROUTES -- AUTH
# Login (/token) and refresh (/token/refresh). Rate-limited per-IP (10/min on login);
# per-account lockout is enforced inside authenticate_user(), not here.
# ==============================================================================
@app.post(
    "/token",
    tags=["auth"],
    summary="Login and obtain a JWT access token",
    responses={
        401: {"description": "Incorrect username or password"},
        423: {"description": "Account locked due to repeated failed logins"},
        429: {"description": "Too many login attempts (per-IP or per-account limit), try again later"},
    },
)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)) -> Token:
    t0 = time.perf_counter()
    # authenticate_user raises HTTPException itself (401 wrong creds, 423 locked out)
    user = await run_in_threadpool(authenticate_user, db, form_data.username, form_data.password)
    access_token = create_access_token(user.username, user.token_version)
    refresh_token = create_refresh_token(user.username, user.token_version)

    logger.info(f"Authentication token generated in {time.perf_counter() - t0:.4f}s")
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@app.post(
    "/token/refresh",
    tags=["auth"],
    summary="Exchange a refresh token for a new access token",
    responses={
        401: {"description": "Refresh token is invalid, expired, or has been revoked"},
    },
)
async def refresh_access_token(body: RefreshRequest, db: Session = Depends(get_db)) -> Token:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token is invalid, expired, or has been revoked",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(body.refresh_token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
    except InvalidTokenError:
        raise unauthorized

    if payload.get("type") != "refresh":
        raise unauthorized

    username = payload.get("sub")
    if username is None:
        raise unauthorized

    user = await run_in_threadpool(_get_user_by_username_sync, db, username)
    if user is None or user.disabled:
        raise unauthorized

    if payload.get("ver") != user.token_version:
        raise unauthorized

    # Rotate both tokens: the old refresh token stops being useful once a new one exists,
    # since re-using it just gets you the same (still-valid) pair again — no extra risk,
    # but a fresh refresh token also means it lives another REFRESH_TOKEN_EXPIRE_DAYS.
    new_access_token = create_access_token(user.username, user.token_version)
    new_refresh_token = create_refresh_token(user.username, user.token_version)
    return Token(access_token=new_access_token, refresh_token=new_refresh_token, token_type="bearer")
 
 
# ==============================================================================
# 17. ROUTES -- USERS (self-service)
# Things a logged-in user can do to their own account: view profile, log out
# everywhere, list their own vehicles.
# ==============================================================================
@app.get("/users/me/", tags=["users"], summary="Get the currently authenticated user")
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)],) -> User:
    return current_user


@app.post(
    "/users/me/logout-all",
    tags=["users"],
    summary="Invalidate every access/refresh token issued to the current user",
    responses={401: {"description": "Not authenticated"}},
)
async def logout_all_sessions(
    current_user: Annotated[UserDB, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
):
    def _bump():
        current_user.token_version += 1
        db.commit()
        return current_user.token_version

    new_version = await run_in_threadpool(_bump)
    return {"detail": "All tokens for this account have been revoked. Log in again to get a new one.", "token_version": new_version}
 
 
@app.get("/users/me/vehicles", tags=["vehicles"], summary="List vehicles owned by the current user")
async def read_my_vehicles(
    current_user: Annotated[UserDB, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
) -> list[VehicleOut]:
    def _list_vehicles():
        return db.query(VehicleDB).filter(VehicleDB.owner_id == current_user.id).all()
 
    vehicles = await run_in_threadpool(_list_vehicles)
    return [
        VehicleOut(vehicle_id=v.vehicle_id, name=v.name, owner_username=current_user.username)
        for v in vehicles
    ]
 
 
# ==============================================================================
# 18. ROUTES -- TELEMETRY
# get_owned_vehicle is the ownership-check dependency used by /api/data below
# (also reusable by admins, who bypass the ownership check).
# ==============================================================================
async def get_owned_vehicle(
    vehicle_id: str,
    current_user: Annotated[UserDB, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
) -> VehicleDB:
    """Resolve a vehicle_id and make sure it belongs to the current user (admins can access any vehicle)."""
    vehicle = await run_in_threadpool(_get_vehicle_sync, db, vehicle_id)
    if vehicle is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Vehicle '{vehicle_id}' not found")
    if not current_user.is_admin and vehicle.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this vehicle")
    return vehicle
 
 
@app.get(
    "/api/data",
    tags=["telemetry"],
    summary="Query vehicle telemetry from InfluxDB",
    description="Returns telemetry as newline-delimited JSON (NDJSON) — one JSON object per line, streamed. "
                 "Note: Swagger UI's 'Response body' viewer shows this as raw text (not pretty-printed JSON) "
                 "because NDJSON is not a single JSON document; each line is independently valid JSON.",
    responses={
        200: {
            "description": "Successful Response (newline-delimited JSON stream)",
            "content": {"application/x-ndjson": {"example": '{"_time": "2026-07-10T12:00:00Z", "_field": "speed", "_value": 42, "vehicle_id": "vehicle-123"}'}},
        },
        400: {"description": "Invalid time range or invalid fields requested"},
        403: {"description": "The vehicle does not belong to the current user"},
        404: {"description": "Vehicle not found"},
        502: {"description": "Failed to query the InfluxDB backend"},
    },
)
@limiter.limit("50/minute")
async def request_data(
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    vehicle_id: Annotated[str, Query(description="Vehicle to fetch telemetry for. Must belong to the current user.")] = ...,
    start_time: Annotated[int, Query(gt=0, description="Start Timestamp Unix Epoch")] = ...,
    stop_time: Annotated[int, Query(gt=0, description="Stop Timestamp Unix Epoch")] = ...,
    limit: Annotated[int, Query(gt=0, le=10000)] = 10000,
    fields: Annotated[Optional[list[str]], Query(description=f"Subset of fields to return. Allowed: {sorted(ALLOWED_FIELDS)}")] = None,
    sort_by: Annotated[str, Query(description="Sort by 'time' (default) or 'value' (the field's measurement, e.g. speed/soc/battery_temp)")] = "time",
    sort_desc: Annotated[bool, Query(description="Sort descending: newest-first for time, biggest-first for value")] = False,
):
    t_start = time.perf_counter()
 
    validate_time_range(start_time, stop_time)
 
    if sort_by not in ("time", "value"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sort_by must be either 'time' or 'value'",
        )
 
    if sort_by == "value" and (not fields or len(fields) != 1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sort_by=value requires exactly one field in 'fields' (sorting mixed fields by value is meaningless, e.g. speed vs soc use different scales)",
        )
 
    # Ownership check: the vehicle must belong to the current user
    await get_owned_vehicle(vehicle_id, current_user, db)
 
    query_api = request.app.state.query_api
    query_params = {
        "p_bucket": bucket,
        "p_start": start_time * 1_000_000_000,
        "p_stop": stop_time * 1_000_000_000,
        "p_measurement": measurement,
        "p_vehicle_id": vehicle_id,
        "p_limit": limit,
    }
 
    query = """
        from(bucket: p_bucket)
        |> range(start: time(v: p_start), stop: time(v: p_stop))
        |> filter(fn: (r) => r._measurement == p_measurement)
        |> filter(fn: (r) => r.vehicle_id == p_vehicle_id)
    """
 
    if fields:
        invalid_fields = set(fields) - ALLOWED_FIELDS
        if invalid_fields:
            logger.warning(f"Invalid fields requested: {invalid_fields}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid fields requested: {sorted(invalid_fields)}. Allowed: {sorted(ALLOWED_FIELDS)}",
            )
 
        field_filter = ' or '.join([f'r._field == "{f}"' for f in fields])
        query += f'|> filter(fn: (r) => {field_filter})\n'
 
    sort_column = "_value" if sort_by == "value" else "_time"
    query += f'|> sort(columns: ["{sort_column}"], desc: {"true" if sort_desc else "false"})\n'
    query += '|> limit(n: p_limit)'
 
    t_query = time.perf_counter()
    try:
        records = await query_api.query_stream(org=org, query=query, params=query_params)
    except Exception as e:
        logger.error(f"InfluxDB query failed: {e}")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to query telemetry backend")
    logger.info(f"InfluxDB stream object initialized in {time.perf_counter() - t_query:.4f}s")
 
    logger.info(f"Data request initialization completed in {time.perf_counter() - t_start:.4f}s")
 
    async def generate():
        t_stream = time.perf_counter()
        record_count = 0
        async for record in records:
            yield json.dumps(record.values, default=str) + "\n"
            record_count += 1
 
        logger.info(f"Stream generation completed: {record_count} records streamed in {time.perf_counter() - t_stream:.4f}s")
 
    return StreamingResponse(generate(), media_type="application/x-ndjson")
 
 
# ==============================================================================
# 19. ROUTES -- ADMIN: USERS
# Everything requiring get_current_admin_user: list/create/update/delete users,
# force-revoke their tokens, clear a lockout. All rate-limited at 20/min.
# ==============================================================================
# -------------------- ADMIN: USERS --------------------
 
@app.get(
    "/admin/users",
    tags=["admin"],
    summary="[Admin] List all users",
    responses={403: {"description": "Admin privileges required"}},
)
@limiter.limit("20/minute")
async def admin_list_users(
    request: Request,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(gt=0, le=1000)] = 1000,
) -> list[User]:
    def _list():
        return db.query(UserDB).offset(skip).limit(limit).all()

    users = await run_in_threadpool(_list)
    return users
 
 
@app.post(
    "/admin/users",
    tags=["admin"],
    status_code=status.HTTP_201_CREATED,
    summary="[Admin] Create a new user",
    responses={
        403: {"description": "Admin privileges required"},
        409: {"description": "Username already exists"},
    },
)
@limiter.limit("20/minute")
async def admin_create_user(
    request: Request,
    new_user: AdminUserCreate,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
) -> User:
    def _create():
        existing = db.query(UserDB).filter(UserDB.username == new_user.username).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Username '{new_user.username}' already exists")
        user = UserDB(
            username=new_user.username,
            hashed_password=get_password_hash(new_user.password),
            disabled=False,
            is_admin=new_user.is_admin,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
 
    return await run_in_threadpool(_create)
 
 
@app.patch(
    "/admin/users/{username}",
    tags=["admin"],
    summary="[Admin] Update a user (disable/enable, reset password [also revokes existing tokens], grant/revoke admin)",
    responses={
        403: {"description": "Admin privileges required"},
        404: {"description": "User not found"},
    },
)
@limiter.limit("20/minute")
async def admin_update_user(
    request: Request,
    username: str,
    update: AdminUserUpdate,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
) -> User:
    def _update():
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found")
 
        if update.password is not None:
            user.hashed_password = get_password_hash(update.password)
            # A password reset should invalidate every token issued before it —
            # otherwise a leaked/compromised account keeps working via its old
            # refresh token for up to REFRESH_TOKEN_EXPIRE_DAYS after the "fix".
            user.token_version += 1
        if update.disabled is not None:
            user.disabled = update.disabled
        if update.is_admin is not None:
            user.is_admin = update.is_admin
 
        db.commit()
        db.refresh(user)
        return user
 
    return await run_in_threadpool(_update)
 
 
@app.delete(
    "/admin/users/{username}",
    tags=["admin"],
    summary="[Admin] Delete a user (also deletes their vehicles)",
    responses={
        400: {"description": "Cannot delete your own admin account"},
        403: {"description": "Admin privileges required"},
        404: {"description": "User not found"},
    },
)
@limiter.limit("20/minute")
async def admin_delete_user(
    request: Request,
    username: str,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
):
    def _delete():
        if username == current_user.username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own admin account")
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found")
        db.delete(user)  # cascades to their vehicles (cascade="all, delete-orphan")
        db.commit()
 
    await run_in_threadpool(_delete)
    return {"detail": f"User '{username}' deleted"}


@app.post(
    "/admin/users/{username}/revoke-tokens",
    tags=["admin"],
    summary="[Admin] Invalidate every access/refresh token issued to a user",
    responses={
        403: {"description": "Admin privileges required"},
        404: {"description": "User not found"},
    },
)
@limiter.limit("20/minute")
async def admin_revoke_user_tokens(
    request: Request,
    username: str,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
):
    def _bump():
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found")
        user.token_version += 1
        db.commit()
        return user.token_version

    new_version = await run_in_threadpool(_bump)
    return {"detail": f"All tokens for '{username}' have been revoked.", "token_version": new_version}


@app.post(
    "/admin/users/{username}/unlock",
    tags=["admin"],
    summary="[Admin] Clear a login lockout and reset failed-attempt count for a user",
    responses={
        403: {"description": "Admin privileges required"},
        404: {"description": "User not found"},
    },
)
@limiter.limit("20/minute")
async def admin_unlock_user(
    request: Request,
    username: str,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
):
    def _unlock():
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found")
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    await run_in_threadpool(_unlock)
    # Also clear the soft per-minute burst window -- otherwise the same
    # recent attempts that caused the hard lock immediately re-trip the
    # 429 the moment the account is unlocked.
    _recent_attempts_by_username.pop(username, None)
    return {"detail": f"'{username}' has been unlocked and can log in normally again."}
 
 
# ==============================================================================
# 20. ROUTES -- ADMIN: VEHICLES
# Same idea as above, for vehicles: admins can manage any vehicle regardless
# of owner, including reassigning ownership.
# ==============================================================================
# -------------------- ADMIN: VEHICLES --------------------
 
@app.get(
    "/admin/vehicles",
    tags=["admin"],
    summary="[Admin] List all vehicles, with their owners",
    responses={403: {"description": "Admin privileges required"}},
)
@limiter.limit("20/minute")
async def admin_list_vehicles(
    request: Request,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(gt=0, le=1000)] = 1000,
) -> list[VehicleOut]:
    def _list():
        return db.query(VehicleDB).offset(skip).limit(limit).all()
 
    vehicles = await run_in_threadpool(_list)
    result = []
    for v in vehicles:
        owner = db.query(UserDB).filter(UserDB.id == v.owner_id).first()
        result.append(VehicleOut(vehicle_id=v.vehicle_id, name=v.name, owner_username=owner.username if owner else "unknown"))
    return result
 
 
@app.post(
    "/admin/vehicles",
    tags=["admin"],
    status_code=status.HTTP_201_CREATED,
    summary="[Admin] Create a vehicle for any user",
    responses={
        403: {"description": "Admin privileges required"},
        404: {"description": "Owner user not found"},
        409: {"description": "A vehicle with this vehicle_id is already registered"},
    },
)
@limiter.limit("20/minute")
async def admin_create_vehicle(
    request: Request,
    vehicle: AdminVehicleCreate,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
) -> VehicleOut:
    def _create():
        owner = db.query(UserDB).filter(UserDB.username == vehicle.owner_username).first()
        if owner is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{vehicle.owner_username}' not found")
 
        new_vehicle = VehicleDB(vehicle_id=vehicle.vehicle_id, name=vehicle.name, owner_id=owner.id)
        db.add(new_vehicle)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Vehicle '{vehicle.vehicle_id}' is already registered")
        db.refresh(new_vehicle)
        return new_vehicle, owner.username
 
    new_vehicle, owner_username = await run_in_threadpool(_create)
    return VehicleOut(vehicle_id=new_vehicle.vehicle_id, name=new_vehicle.name, owner_username=owner_username)
 
 
@app.patch(
    "/admin/vehicles/{vehicle_id}",
    tags=["admin"],
    summary="[Admin] Update a vehicle's name and/or owner (no ownership restriction)",
    responses={
        403: {"description": "Admin privileges required"},
        404: {"description": "Vehicle or new owner not found"},
    },
)
@limiter.limit("20/minute")
async def admin_update_vehicle(
    request: Request,
    vehicle_id: str,
    update: AdminVehicleUpdate,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
) -> VehicleOut:
    def _update():
        vehicle = db.query(VehicleDB).filter(VehicleDB.vehicle_id == vehicle_id).first()
        if vehicle is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Vehicle '{vehicle_id}' not found")
 
        if update.name is not None:
            vehicle.name = update.name
 
        if update.owner_username is not None:
            new_owner = db.query(UserDB).filter(UserDB.username == update.owner_username).first()
            if new_owner is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{update.owner_username}' not found")
            vehicle.owner_id = new_owner.id
 
        db.commit()
        db.refresh(vehicle)
        owner = db.query(UserDB).filter(UserDB.id == vehicle.owner_id).first()
        return vehicle.vehicle_id, vehicle.name, owner.username
 
    vehicle_id_out, name_out, owner_username = await run_in_threadpool(_update)
    return VehicleOut(vehicle_id=vehicle_id_out, name=name_out, owner_username=owner_username)
 
 
@app.delete(
    "/admin/vehicles/{vehicle_id}",
    tags=["admin"],
    summary="[Admin] Delete any vehicle",
    responses={
        403: {"description": "Admin privileges required"},
        404: {"description": "Vehicle not found"},
    },
)
@limiter.limit("20/minute")
async def admin_delete_vehicle(
    request: Request,
    vehicle_id: str,
    current_user: Annotated[UserDB, Depends(get_current_admin_user)],
    db: Session = Depends(get_db),
):
    def _delete():
        vehicle = db.query(VehicleDB).filter(VehicleDB.vehicle_id == vehicle_id).first()
        if vehicle is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Vehicle '{vehicle_id}' not found")
        db.delete(vehicle)
        db.commit()
 
    await run_in_threadpool(_delete)
    return {"detail": f"Vehicle '{vehicle_id}' deleted"}
    # Verified: dependencies bumped, tests passing (CI green)