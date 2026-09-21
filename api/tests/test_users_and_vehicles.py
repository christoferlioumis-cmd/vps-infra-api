from conftest import auth_headers, make_user
from database import VehicleDB


def _add_vehicle(db_session, owner, vehicle_id="veh-1", name="Truck"):
    v = VehicleDB(vehicle_id=vehicle_id, name=name, owner_id=owner.id)
    db_session.add(v)
    db_session.commit()
    db_session.refresh(v)
    return v


def test_user_sees_only_their_own_vehicles(client, db_session):
    alice = make_user(db_session, username="alice", password="alicepass123")
    bob = make_user(db_session, username="bob2", password="bobpass123")
    _add_vehicle(db_session, alice, "veh-alice", "Alice's car")
    _add_vehicle(db_session, bob, "veh-bob", "Bob's car")

    headers = auth_headers(client, "alice", "alicepass123")
    resp = client.get("/users/me/vehicles", headers=headers)

    assert resp.status_code == 200
    vehicle_ids = [v["vehicle_id"] for v in resp.json()]
    assert vehicle_ids == ["veh-alice"]


def test_user_cannot_access_another_users_vehicle_telemetry(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    bob = make_user(db_session, username="bob2", password="bobpass123")
    _add_vehicle(db_session, bob, "veh-bob")

    headers = auth_headers(client, "alice", "alicepass123")
    resp = client.get(
        "/api/data",
        params={"vehicle_id": "veh-bob", "start_time": 1, "stop_time": 2},
        headers=headers,
    )

    assert resp.status_code == 403


def test_telemetry_query_for_nonexistent_vehicle_is_404(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    headers = auth_headers(client, "alice", "alicepass123")

    resp = client.get(
        "/api/data",
        params={"vehicle_id": "does-not-exist", "start_time": 1, "stop_time": 2},
        headers=headers,
    )

    assert resp.status_code == 404


def test_telemetry_streams_fake_influx_records(client, db_session, fake_query_api):
    alice = make_user(db_session, username="alice", password="alicepass123")
    _add_vehicle(db_session, alice, "veh-alice")
    fake_query_api.records = [
        {"_time": "2026-01-01T00:00:00Z", "_field": "speed", "_value": 42, "vehicle_id": "veh-alice"},
        {"_time": "2026-01-01T00:01:00Z", "_field": "speed", "_value": 50, "vehicle_id": "veh-alice"},
    ]
    headers = auth_headers(client, "alice", "alicepass123")

    resp = client.get(
        "/api/data",
        params={"vehicle_id": "veh-alice", "start_time": 1, "stop_time": 2},
        headers=headers,
    )

    assert resp.status_code == 200
    lines = [line for line in resp.text.strip().split("\n") if line]
    assert len(lines) == 2
    assert fake_query_api.last_call["params"]["p_vehicle_id"] == "veh-alice"


def test_telemetry_returns_502_when_influx_query_fails(client, db_session, fake_query_api):
    alice = make_user(db_session, username="alice", password="alicepass123")
    _add_vehicle(db_session, alice, "veh-alice")
    fake_query_api.raises = RuntimeError("influx is down")
    headers = auth_headers(client, "alice", "alicepass123")

    resp = client.get(
        "/api/data",
        params={"vehicle_id": "veh-alice", "start_time": 1, "stop_time": 2},
        headers=headers,
    )

    assert resp.status_code == 502


def test_telemetry_rejects_invalid_time_range(client, db_session):
    alice = make_user(db_session, username="alice", password="alicepass123")
    _add_vehicle(db_session, alice, "veh-alice")
    headers = auth_headers(client, "alice", "alicepass123")

    resp = client.get(
        "/api/data",
        params={"vehicle_id": "veh-alice", "start_time": 5, "stop_time": 1},
        headers=headers,
    )

    assert resp.status_code == 400


def test_non_admin_cannot_use_admin_endpoints(client, db_session):
    make_user(db_session, username="alice", password="alicepass123")
    headers = auth_headers(client, "alice", "alicepass123")

    resp = client.get("/admin/users", headers=headers)

    assert resp.status_code == 403


def test_admin_can_create_update_and_delete_user(client, admin_user):
    headers = auth_headers(client, "admin", "adminpass123")

    create_resp = client.post(
        "/admin/users",
        json={"username": "newguy", "password": "newguypass123", "is_admin": False},
        headers=headers,
    )
    assert create_resp.status_code == 201

    update_resp = client.patch(
        "/admin/users/newguy",
        json={"disabled": True},
        headers=headers,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["disabled"] is True

    delete_resp = client.delete("/admin/users/newguy", headers=headers)
    assert delete_resp.status_code == 200


def test_admin_cannot_delete_own_account(client, admin_user):
    headers = auth_headers(client, "admin", "adminpass123")
    resp = client.delete("/admin/users/admin", headers=headers)
    assert resp.status_code == 400


def test_admin_create_user_duplicate_username_conflicts(client, admin_user):
    headers = auth_headers(client, "admin", "adminpass123")
    client.post("/admin/users", json={"username": "dup", "password": "duppass123"}, headers=headers)

    resp = client.post("/admin/users", json={"username": "dup", "password": "duppass123"}, headers=headers)

    assert resp.status_code == 409


def test_admin_can_manage_any_vehicle(client, admin_user, regular_user):
    headers = auth_headers(client, "admin", "adminpass123")

    create_resp = client.post(
        "/admin/vehicles",
        json={"vehicle_id": "veh-admin-created", "name": "Fleet car", "owner_username": "bob"},
        headers=headers,
    )
    assert create_resp.status_code == 201

    list_resp = client.get("/admin/vehicles", headers=headers)
    assert list_resp.status_code == 200
    assert any(v["vehicle_id"] == "veh-admin-created" for v in list_resp.json())

    delete_resp = client.delete("/admin/vehicles/veh-admin-created", headers=headers)
    assert delete_resp.status_code == 200


def test_disabled_user_cannot_authenticate_use_endpoints(client, db_session):
    make_user(db_session, username="disabled_user", password="pass123456", disabled=True)
    headers = auth_headers(client, "disabled_user", "pass123456")

    resp = client.get("/users/me/", headers=headers)

    assert resp.status_code == 400