from app import app, login_required


def test_login_required_allows_anonymous_mode(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "")

    protected = login_required(lambda: "allowed")
    with app.test_request_context("/"):
        assert protected() == "allowed"


def test_index_is_available_without_sso(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "")

    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b'"authenticated": true' in response.data


def test_login_required_enforces_configured_sso(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "client-id")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "tenant-id")

    protected = login_required(lambda: "allowed")
    with app.test_request_context("/api/test", headers={"Accept": "application/json"}):
        response, status = protected()

    assert status == 401
    assert response.get_json()["error"] == "Authentication required."