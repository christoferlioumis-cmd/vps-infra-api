from conftest import auth_headers, make_user


def test_login_success_returns_token_pair(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")

    resp = client.post("/token", data={"username": "alice", "password": "alicepass123"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]


def test_login_wrong_password_returns_401(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")

    resp = client.post("/token", data={"username": "alice", "password": "wrong"})

    assert resp.status_code == 401


def test_login_unknown_username_returns_401_not_404(client):
    """Unknown usernames must look identical to wrong passwords (no user enumeration)."""
    resp = client.post("/token", data={"username": "nobody", "password": "whatever"})
    assert resp.status_code == 401


def test_get_current_user_requires_token(client):
    resp = client.get("/users/me/")
    assert resp.status_code == 401


def test_get_current_user_with_valid_token(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    headers = auth_headers(client, "alice", "alicepass123")

    resp = client.get("/users/me/", headers=headers)

    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"


def test_account_locks_after_max_failed_attempts(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")

    # MAX_FAILED_LOGIN_ATTEMPTS is 5; each request also needs to dodge the
    # 3/minute *account* rate limit, so space attempts out isn't necessary
    # here since the account rate limit itself also counts toward lockout.
    statuses = []
    for _ in range(6):
        resp = client.post("/token", data={"username": "alice", "password": "wrong"})
        statuses.append(resp.status_code)

    # Once locked, the account should return 423, not 401/429.
    assert 423 in statuses
    lock_index = statuses.index(423)
    assert all(s == 423 for s in statuses[lock_index:])


def test_locked_account_rejects_even_correct_password(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    for _ in range(6):
        client.post("/token", data={"username": "alice", "password": "wrong"})

    resp = client.post("/token", data={"username": "alice", "password": "alicepass123"})
    assert resp.status_code == 423


def test_nonexistent_username_also_locks_out_like_a_real_one(client):
    """
    Phantom lockout: hammering a username that doesn't exist should behave
    identically (423 after N attempts) to hammering a real one, so an
    attacker can't distinguish "wrong password" from "no such user" by
    watching for when lockout kicks in.
    """
    statuses = []
    for _ in range(6):
        resp = client.post("/token", data={"username": "ghost", "password": "whatever"})
        statuses.append(resp.status_code)

    assert 423 in statuses


def test_admin_unlock_clears_lockout(client, db_session, admin_user):
    make_user(db_session, username="alice", password="alicepass123")
    for _ in range(6):
        client.post("/token", data={"username": "alice", "password": "wrong"})
    assert client.post("/token", data={"username": "alice", "password": "alicepass123"}).status_code == 423

    admin_headers = auth_headers(client, "admin", "adminpass123")
    unlock_resp = client.post("/admin/users/alice/unlock", headers=admin_headers)
    assert unlock_resp.status_code == 200

    resp = client.post("/token", data={"username": "alice", "password": "alicepass123"})
    assert resp.status_code == 200


def test_refresh_token_issues_new_access_token(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    tokens = client.post("/token", data={"username": "alice", "password": "alicepass123"}).json()

    resp = client.post("/token/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["access_token"]
    assert new_tokens["refresh_token"]


def test_access_token_cannot_be_used_as_refresh_token(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    tokens = client.post("/token", data={"username": "alice", "password": "alicepass123"}).json()

    resp = client.post("/token/refresh", json={"refresh_token": tokens["access_token"]})

    assert resp.status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    tokens = client.post("/token", data={"username": "alice", "password": "alicepass123"}).json()

    resp = client.get("/users/me/", headers={"Authorization": f"Bearer {tokens['refresh_token']}"})

    assert resp.status_code == 401


def test_logout_all_revokes_existing_tokens(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    headers = auth_headers(client, "alice", "alicepass123")

    logout_resp = client.post("/users/me/logout-all", headers=headers)
    assert logout_resp.status_code == 200

    # The token used to call logout-all was valid for that one call, but is
    # now stale (token_version bumped) -- using it again must fail.
    resp = client.get("/users/me/", headers=headers)
    assert resp.status_code == 401
    # Verified: all auth tests pass in CI