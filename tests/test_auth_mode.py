from types import SimpleNamespace

import pytest

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


def test_about_dialog_reflects_configured_limits(monkeypatch):
    monkeypatch.setattr('app.AZURE_CLIENT_ID', '')
    monkeypatch.setattr('app.AZURE_TENANT_ID', '')
    monkeypatch.setitem(app.config, 'MAX_CONTENT_LENGTH', 12_500_000_000)
    monkeypatch.setattr('app.MAX_ARCHIVE_EXTRACTED_SIZE', 8_000_000_000)
    monkeypatch.setattr('app.MAX_ARCHIVE_ENTRIES', 42000)
    monkeypatch.setattr('app.SESSION_TIMEOUT_MINUTES_FILE', 45)
    monkeypatch.setattr('app.MAX_TOTAL_STORAGE', 25 * 1024 ** 3)

    response = app.test_client().get('/')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'Uploads up to 12.5 GB' in html
    assert '8 GB extracted and 42,000 entries per archive' in html
    assert '45 minutes of session inactivity' in html
    assert '25 GiB temporary storage budget' in html
    assert 'LiquidFiles email delivery to multiple recipients' in html
    assert 'dedicated API account' in html
    assert '3GB per session' not in html


def test_login_required_enforces_configured_sso(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "client-id")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "tenant-id")

    protected = login_required(lambda: "allowed")
    with app.test_request_context("/api/test", headers={"Accept": "application/json"}):
        response, status = protected()

    assert status == 401
    assert response.get_json()["error"] == "Authentication required."


@pytest.mark.parametrize("total_gib,free_gib,low_space", [
    (100, 4, True),
    (10, 2, True),
    (100, 10, False),
    (60, 3, False),
])
def test_storage_status_checks_actual_disk_space(monkeypatch, total_gib, free_gib, low_space):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "")
    gib = 1024 ** 3
    checked_paths = []

    def disk_usage(path):
        checked_paths.append(path)
        return SimpleNamespace(total=total_gib * gib, free=free_gib * gib)

    monkeypatch.setattr("app.shutil.disk_usage", disk_usage)
    response = app.test_client().get("/api/storage")
    assert response.status_code == 200
    assert response.get_json()["low_space"] is low_space
    assert response.get_json()["free_bytes"] == free_gib * gib
    assert response.get_json()["free_percent"] == pytest.approx(free_gib / total_gib * 100)
    assert response.headers["Cache-Control"] == "no-store"
    assert checked_paths == [app.config[key] for key in ("UPLOAD_FOLDER", "OUTPUT_FOLDER", "CHUNK_FOLDER")]


def test_storage_status_detects_low_chunk_filesystem(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "")
    monkeypatch.setattr("app.shutil.disk_usage", lambda path: SimpleNamespace(
        total=100 * 1024 ** 3,
        free=(1 if path == app.config["CHUNK_FOLDER"] else 10) * 1024 ** 3,
    ))
    response = app.test_client().get("/api/storage")
    assert response.status_code == 200
    assert response.get_json()["low_space"] is True
    assert response.get_json()["free_bytes"] == 1024 ** 3


def test_storage_status_requires_login_when_sso_configured(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "client-id")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "tenant-id")
    response = app.test_client().get("/api/storage")
    assert response.status_code == 401


def test_storage_status_reports_unavailable_disk(monkeypatch):
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "")

    def disk_usage(path):
        raise OSError("Disk unavailable")

    monkeypatch.setattr("app.shutil.disk_usage", disk_usage)
    response = app.test_client().get("/api/storage")
    assert response.status_code == 503
    assert response.get_json()["error"] == "Server disk status unavailable."