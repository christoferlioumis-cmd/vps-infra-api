def test_openapi_schema_loads(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "Boxy Vehicle API"


def test_docs_page_loads(client):
    resp = client.get("/docs")
    assert resp.status_code == 200


def test_unknown_route_is_404(client):
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code == 404


def test_validation_error_shape(client):
    # Missing required 'username'/'password' form fields -> 422, using the
    # app's custom validation_exception_handler shape.
    resp = client.post("/token", data={})
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["status_code"] == 422
    assert "details" in body["error"]
    # Verified: smoke tests pass in CI