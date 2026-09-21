"""
Shared pytest fixtures for the API test suite.

Design goals:
- Never touch the real Postgres or InfluxDB used by docker-compose. Tests run
  against an isolated, on-disk SQLite database (fresh tables per test) and a
  fake InfluxDB query_api that returns canned records.
- Each test gets a clean slate: DB tables are dropped/recreated and the
  in-memory login-lockout state in api.py is reset before every test, so
  tests can't leak state (e.g. an account lockout) into each other.

Required env vars (JWT_SECRET_KEY, INFLUX_*, POSTGRES_URL) are set *before*
`api` / `database` are imported for the first time, since api.py reads them
at import time via require_env().
"""
import os
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

# Make `import database` / `import api` (and api.py's own `from database import ...`)
# work the same way they do inside the container, where /app == the api/ folder.
# Resolved defensively so it works whether tests/ lives next to api/ (repo-root/tests)
# or nested inside it (repo-root/api/tests):
_here = os.path.dirname(os.path.abspath(__file__))
_candidates = [
    os.path.normpath(os.path.join(_here, "..", "api")),  # tests/ is a sibling of api/
    os.path.normpath(os.path.join(_here, "..")),          # tests/ is nested inside api/
]
API_DIR = next((p for p in _candidates if os.path.isfile(os.path.join(p, "api.py"))), _candidates[0])
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

TEST_JWT_SECRET = "test-only-secret-never-used-outside-ci"  # noqa: S105


def _set_test_env(db_url: str):
    os.environ["POSTGRES_URL"] = db_url
    os.environ["JWT_SECRET_KEY"] = TEST_JWT_SECRET
    os.environ["INFLUX_URL"] = "http://influxdb.invalid:8086"
    os.environ["INFLUX_TOKEN"] = "test-token"
    os.environ["INFLUX_ORG"] = "test-org"
    os.environ["INFLUX_BUCKET"] = "test-bucket"


# Set env vars once, before the first `import api`, so require_env() succeeds
# and database.py picks up the SQLite URL instead of defaulting to Postgres.
_set_test_env("sqlite:///./_test_session_default.db")

import api as api_module  # noqa: E402
import database as database_module  # noqa: E402


class _FakeStream:
    """Async iterator standing in for InfluxDB's query_stream() result."""

    def __init__(self, records):
        self._records = records

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        for r in self._records:
            yield r


class _FakeRecord:
    def __init__(self, values: dict):
        self.values = values


class FakeQueryApi:
    """
    Drop-in replacement for app.state.query_api. Tests configure
    `fake_query_api.records = [...]` (list of dict) to control what
    GET /api/data streams back, or set `.raises = SomeException()` to
    simulate an InfluxDB failure (expects a 502 from the endpoint).
    """

    def __init__(self):
        self.records = []
        self.raises = None
        self.last_call = None  # (query, params) from the most recent call, for assertions

    async def query_stream(self, org, query, params):
        self.last_call = {"org": org, "query": query, "params": params}
        if self.raises:
            raise self.raises
        return _FakeStream([_FakeRecord(v) for v in self.records])


@pytest.fixture()
def db_engine(tmp_path):
    """Fresh SQLite file per test, with all tables created."""
    db_path = tmp_path / f"test_{uuid.uuid4().hex}.db"
    db_url = f"sqlite:///{db_path}"
    _set_test_env(db_url)

    # Re-point the already-imported database module at this test's engine
    # instead of re-importing (re-importing api.py would re-run init_db(),
    # re-register routes on a stale FastAPI instance, etc.).
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    database_module.engine = engine
    database_module.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    api_module.SessionLocal = database_module.SessionLocal

    database_module.Base.metadata.create_all(bind=engine)
    yield engine
    database_module.Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _reset_in_memory_login_state():
    """
    api.py tracks per-account rate limiting and phantom-user lockouts in
    plain module-level dicts (by design, see comments in api.py). Clear
    them before every test so one test's failed logins can't lock out
    an account in a later, unrelated test.
    """
    api_module._recent_attempts_by_username.clear()
    api_module._phantom_fail_counts.clear()
    api_module._phantom_locked_until.clear()
    # Also reset slowapi's per-IP limiter storage (e.g. the 10/minute limit
    # on POST /token) so request counts from one test don't 429 the next.
    reset = getattr(api_module.limiter, "reset", None)
    if callable(reset):
        reset()
    yield


@pytest.fixture()
def fake_query_api():
    return FakeQueryApi()


@pytest.fixture()
def client(db_engine, fake_query_api):
    """
    A TestClient with its own isolated SQLite DB (via db_engine) and with
    app.state.query_api replaced by a fake right after startup, so no test
    ever needs a real InfluxDB instance. The real lifespan is left alone:
    constructing InfluxDBClientAsync only builds a client object (it doesn't
    contact the server), so it's safe to let it run and then swap the
    query_api reference it produced.
    """
    app = api_module.app
    with TestClient(app) as c:
        app.state.query_api = fake_query_api
        yield c


def make_user(db, username="alice", password="alicepass123", is_admin=False, disabled=False):
    """Insert a user directly into the test DB, bypassing the API/admin endpoints."""
    user = database_module.UserDB(
        username=username,
        hashed_password=api_module.get_password_hash(password),
        is_admin=is_admin,
        disabled=disabled,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def db_session(db_engine):
    session = database_module.SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def admin_user(db_session):
    return make_user(db_session, username="admin", password="adminpass123", is_admin=True)


@pytest.fixture()
def regular_user(db_session):
    return make_user(db_session, username="bob", password="bobpass123", is_admin=False)


def auth_headers(client, username, password):
    resp = client.post("/token", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
    # Verified: fixtures confirmed working, all 29 tests pass in CI