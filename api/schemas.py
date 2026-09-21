"""
Pydantic models (request/response schemas) used by api.py.

Kept separate from api.py so the endpoint logic isn't mixed together
with the data validation rules. If you're adding a new endpoint that
needs a new request body or response shape, define it here and import
it into api.py — don't define models directly inside api.py.
"""

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Auth (login / JWT)
# ---------------------------------------------------------------------------

class Token(BaseModel):
    """What POST /token returns after a successful login: the JWT(s)."""
    access_token: str
    refresh_token: str
    token_type: str  # always "bearer" in this API


class RefreshRequest(BaseModel):
    """Request body for POST /token/refresh — trade a refresh token for a new access token."""
    refresh_token: str


class TokenData(BaseModel):
    """
    What we decode OUT of a JWT payload when checking who's making a request.
    Not returned to the client — used internally by get_current_user().
    """
    username: str | None = None


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class User(BaseModel):
    """
    Public-facing shape of a user, e.g. what GET /users/me/ returns.
    Never include hashed_password here — this is what gets sent back
    to the client, and the password hash should never leave the server.
    """
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    is_admin: bool | None = None

    # Lets us build this directly from a UserDB SQLAlchemy object
    # (model.username, model.is_admin, etc.) instead of a plain dict.
    model_config = ConfigDict(from_attributes=True)


class AdminUserCreate(BaseModel):
    """Request body for POST /admin/users (admin creates a new user)."""
    username: str = Field(
        min_length=3,
        max_length=32,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="3-32 characters, letters/digits/underscore/hyphen only",
    )
    password: str = Field(min_length=6, max_length=128, description="At least 6 characters")
    is_admin: bool = False


class AdminUserUpdate(BaseModel):
    """
    Request body for PATCH /admin/users/{username}.
    Every field is optional — only the fields the admin actually sends
    get changed (partial update), everything else on the user stays as-is.
    """
    password: str | None = Field(default=None, min_length=6, max_length=128, description="At least 6 characters, if provided")
    disabled: bool | None = None
    is_admin: bool | None = None


# ---------------------------------------------------------------------------
# Vehicles
# ---------------------------------------------------------------------------

class VehicleOut(BaseModel):
    """Public-facing shape of a vehicle, returned by the vehicle endpoints."""
    vehicle_id: str
    name: str | None = None
    owner_username: str  # resolved from the owner_id foreign key before returning

    model_config = ConfigDict(from_attributes=True)


class AdminVehicleCreate(BaseModel):
    """Request body for POST /admin/vehicles (admin registers a vehicle for any user)."""
    vehicle_id: str
    name: str | None = None
    owner_username: str


class AdminVehicleUpdate(BaseModel):
    """
    Request body for PATCH /admin/vehicles/{vehicle_id}.
    Both fields optional (partial update). Setting owner_username here
    is how ownership gets transferred from one user to another.
    """
    name: str | None = None
    owner_username: str | None = None
    # Verified: line endings normalized, tests passing (CI green)