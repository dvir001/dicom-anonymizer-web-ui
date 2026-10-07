import os
import io
import zipfile
import time
from unittest.mock import Mock

import pytest
import requests

from app import app, _ensure_dicom_filename, _compute_unique_dicom_rel_path


def test_ensure_dicom_filename_enforces_extension():
    assert _ensure_dicom_filename("scan.dcm") == "scan.dcm"
    assert _ensure_dicom_filename("scan") == "scan.dcm"
    # Already normalized names should be preserved
    assert _ensure_dicom_filename("scan.dcm") == "scan.dcm"


def test_compute_unique_path_preserves_directory_structure():
    used = set()
    rel_path = os.path.join("study", "series", "image1.dcm")
    normalized = _compute_unique_dicom_rel_path(rel_path, used)

    assert normalized.endswith(".dcm")
    assert normalized.startswith(os.path.join("study", "series"))


def test_compute_unique_path_adds_suffix_for_collisions():
    used = set()
    first = _compute_unique_dicom_rel_path("image.dcm", used)
    second = _compute_unique_dicom_rel_path("image", used)

    assert first == "image.dcm"
    assert second == "image-1.dcm"


def test_compute_unique_path_handles_missing_filename():
    used = set()
    rel_path = os.path.join("study", ".dcm")
    normalized = _compute_unique_dicom_rel_path(rel_path, used)

    assert normalized.endswith("dcm")
    assert os.path.basename(normalized).startswith("dicom_file")


@pytest.fixture(params=[2, 97])
def download_batch(tmp_path, monkeypatch, request):
    monkeypatch.setitem(app.config, "OUTPUT_FOLDER", str(tmp_path))
    monkeypatch.setattr("app.AZURE_CLIENT_ID", "")
    monkeypatch.setattr("app.AZURE_TENANT_ID", "")
    monkeypatch.setattr("app._record_session_activity", lambda *args, **kwargs: None)
    session_id = "a" * 32
    output_dir = tmp_path / session_id / "study"
    output_dir.mkdir(parents=True)
    (output_dir / "first.dcm").write_bytes(b"first scan")
    (output_dir / "second.dcm").write_bytes(b"second scan")
    for index in range(2, request.param):
        (output_dir / f"scan-{index}.dcm").write_bytes(b"scan data")
    return app.test_client(), session_id, tmp_path


def test_download_retries_failed_zip_build(download_batch, monkeypatch):
    client, session_id, output_root = download_batch
    original_write = zipfile.ZipFile.write
    writes = []

    def interrupted_write(archive, filename, *args, **kwargs):
        assert not (output_root / f"{session_id}_anonymized.zip").exists()
        writes.append(filename)
        if len(writes) == 2:
            raise OSError("Interrupted archive creation")
        return original_write(archive, filename, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "write", interrupted_write)
    response = client.get(f"/download/{session_id}")
    assert response.status_code == 500
    response.close()
    assert list(output_root.glob("*.tmp")) == []

    monkeypatch.setattr(zipfile.ZipFile, "write", original_write)
    response = client.get(f"/download/{session_id}")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        expected = {
            path.relative_to(output_root / session_id).as_posix()
            for path in (output_root / session_id).rglob("*.dcm")
        }
        assert set(archive.namelist()) == expected
        assert archive.testzip() is None
    response.close()
    assert list(output_root.glob("*.tmp")) == []


@pytest.mark.parametrize('sso_email', [None, '', 'not-an-email', 'sso-user@example.com'])
def test_liquidfiles_sends_only_anonymized_output(liquidfiles_batch, monkeypatch, sso_email):
    client, session_id, _ = liquidfiles_batch
    with client.session_transaction() as browser_session:
        browser_session['user_email'] = sso_email
    calls = []

    class ApiResponse:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self.payload

    def post(api_client, url, **kwargs):
        assert api_client.auth == ('test-secret', 'x')
        assert api_client.headers['Accept'] == 'application/json'
        assert kwargs['allow_redirects'] is False
        calls.append(url)
        if url.endswith('/upload'):
            assert kwargs['params']['filename'].endswith('-dicom.zip')
            with zipfile.ZipFile(io.BytesIO(kwargs['data'].read())) as archive:
                assert 'study/first.dcm' in archive.namelist()
                assert archive.read('study/first.dcm') == b'first scan'
            return ApiResponse({'attachment': {'id': 'attachment-id'}})
        message = kwargs['json']['message']
        assert 'sender' not in message
        assert message['recipients'] == ['recipient@example.com']
        assert message['attachments'] == ['attachment-id']
        assert message['send_email'] is True
        assert message['authorization'] == 3
        return ApiResponse({'message': {'id': 'message-id'}})

    monkeypatch.setattr('app.requests.Session.post', post)
    response = client.post(f'/send-liquidfiles/{session_id}', json={
        'email': 'recipient@example.com', 'sender': 'spoofed@example.com',
    })
    assert response.status_code == 200
    assert response.json == {'success': True}
    assert calls == [
        'https://files.example.com/message/attachments/upload',
        'https://files.example.com/message',
    ]


def test_download_supports_resuming_zip(download_batch):
    client, session_id, _ = download_batch
    response = client.get(f"/download/{session_id}")
    archive_bytes = response.data
    etag = response.headers["ETag"]
    response.close()

    response = client.get(
        f"/download/{session_id}",
        headers={"Range": "bytes=10-", "If-Range": etag},
    )
    assert response.status_code == 206
    assert response.data == archive_bytes[10:]
    assert response.headers["ETag"] == etag
    response.close()


@pytest.mark.parametrize("invalid_cache", ["incomplete", "corrupt"])
def test_download_rebuilds_invalid_cached_zip(download_batch, invalid_cache):
    client, session_id, output_root = download_batch
    zip_path = output_root / f"{session_id}_anonymized.zip"
    if invalid_cache == "incomplete":
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.write(output_root / session_id / "study" / "first.dcm", "study/first.dcm")
    else:
        zip_path.write_bytes(b"interrupted ZIP")

    response = client.get(f"/download/{session_id}")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert len(archive.namelist()) == len(list((output_root / session_id).rglob("*.dcm")))
        assert archive.testzip() is None
    response.close()


@pytest.fixture
def liquidfiles_batch(download_batch, monkeypatch):
    client, session_id, output_root = download_batch
    monkeypatch.setattr('app.LIQUIDFILES_URL', 'https://files.example.com')
    monkeypatch.setattr('app.LIQUIDFILES_API_KEY', 'test-secret')
    monkeypatch.setattr('app.AZURE_CLIENT_ID', 'client-id')
    monkeypatch.setattr('app.AZURE_TENANT_ID', 'tenant-id')
    with client.session_transaction() as browser_session:
        browser_session['output_sessions'] = [session_id]
        browser_session['authenticated'] = True
        browser_session['login_time'] = time.time()
        browser_session['user_email'] = 'sso-user@example.com'
    return client, session_id, output_root


@pytest.mark.parametrize('email', [None, '', 'not-an-email', 'user@example.com\r\nBcc:other@example.com', ['user@example.com']])
def test_liquidfiles_rejects_invalid_recipient(liquidfiles_batch, monkeypatch, email):
    client, session_id, _ = liquidfiles_batch

    def unexpected_post(*args, **kwargs):
        pytest.fail('Invalid recipients must not reach LiquidFiles')

    monkeypatch.setattr('app.requests.Session.post', unexpected_post)
    response = client.post(f'/send-liquidfiles/{session_id}', json={'email': email})
    assert response.status_code == 400


def test_liquidfiles_rejects_unowned_batch(liquidfiles_batch):
    client, session_id, _ = liquidfiles_batch
    with client.session_transaction() as browser_session:
        browser_session['output_sessions'] = []
    response = client.post(f'/send-liquidfiles/{session_id}', json={'email': 'user@example.com'})
    assert response.status_code == 403


@pytest.mark.parametrize('url,key', [('', ''), ('https://files.example.com', ''), ('http://files.example.com', 'key')])
def test_liquidfiles_requires_secure_configuration(liquidfiles_batch, monkeypatch, url, key):
    client, session_id, _ = liquidfiles_batch
    monkeypatch.setattr('app.LIQUIDFILES_URL', url)
    monkeypatch.setattr('app.LIQUIDFILES_API_KEY', key)
    response = client.post(f'/send-liquidfiles/{session_id}', json={'email': 'user@example.com'})
    assert response.status_code == 503


@pytest.mark.parametrize('failure,status', [
    (requests.Timeout('test-secret'), 504),
    (requests.HTTPError('test-secret'), 502),
    (ValueError('test-secret'), 502),
])
def test_liquidfiles_failure_does_not_leak_credentials(liquidfiles_batch, monkeypatch, failure, status):
    client, session_id, _ = liquidfiles_batch

    def failing_post(*args, **kwargs):
        raise failure

    monkeypatch.setattr('app.requests.Session.post', failing_post)
    response = client.post(f'/send-liquidfiles/{session_id}', json={'email': 'user@example.com'})
    assert response.status_code == status
    assert 'test-secret' not in response.get_data(as_text=True)
    assert client.get(f'/download/{session_id}').status_code == 200


def test_liquidfiles_expired_batch(liquidfiles_batch):
    client, _, _ = liquidfiles_batch
    expired_id = 'b' * 32
    with client.session_transaction() as browser_session:
        browser_session['output_sessions'] = [expired_id]
    response = client.post(f'/send-liquidfiles/{expired_id}', json={'email': 'user@example.com'})
    assert response.status_code == 404


def test_anonymization_records_output_ownership(download_batch, monkeypatch):
    client, session_id, output_root = download_batch
    upload_root = output_root / 'uploads'
    source_dir = upload_root / session_id
    source_dir.mkdir(parents=True)
    (source_dir / 'source.dcm').write_bytes(b'input scan')
    monkeypatch.setitem(app.config, 'UPLOAD_FOLDER', str(upload_root))
    monkeypatch.setattr('app.is_dicom_file', lambda path: True)

    def make_test_directory(path):
        os.makedirs(path, exist_ok=True)
        return True

    monkeypatch.setattr('app.safe_makedirs', make_test_directory)

    def anonymize(source, output, *args, **kwargs):
        with open(output, 'wb') as destination:
            destination.write(b'anonymized scan')

    monkeypatch.setattr('app.anonymize_dicom_file', anonymize)
    response = client.post('/anonymize', json={'session_id': session_id})
    assert response.status_code == 200
    with client.session_transaction() as browser_session:
        assert response.json['output_session_id'] in browser_session['output_sessions']


def test_liquidfiles_setting_is_public_but_key_is_not(liquidfiles_batch):
    client, _, _ = liquidfiles_batch
    response = client.get('/')
    assert response.status_code == 200
    assert '"liquidfilesConfigured": true' in response.get_data(as_text=True)
    assert 'test-secret' not in response.get_data(as_text=True)


def test_liquidfiles_sends_multiple_recipients(liquidfiles_batch, monkeypatch):
    client, session_id, _ = liquidfiles_batch
    calls = []

    class ApiResponse:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self.payload

    def post(api_client, url, **kwargs):
        calls.append(url)
        if url.endswith('/upload'):
            return ApiResponse({'attachment': {'id': 'attachment-id'}})
        message = kwargs['json']['message']
        assert 'sender' not in message
        assert message['recipients'] == ['alice@example.com', 'bob@example.com']
        assert message['authorization'] == 3
        assert message['send_email'] is True
        return ApiResponse({'message': {'id': 'message-id'}})

    monkeypatch.setattr('app.requests.Session.post', post)
    response = client.post(f'/send-liquidfiles/{session_id}', json={
        'recipients': ['alice@example.com', ' bob@example.com ', 'alice@example.com'],
    })
    assert response.status_code == 200
    assert len(calls) == 2


@pytest.mark.parametrize('recipients', [
    [], None, 'alice@example.com', ['alice@example.com', 'invalid'],
    ['alice@example.com', None], ['alice@example.com', ''],
    ['alice@example.com', 'bob@example.com\r\nBcc:mallory@example.com'],
])
def test_liquidfiles_rejects_invalid_recipient_lists(liquidfiles_batch, monkeypatch, recipients):
    client, session_id, _ = liquidfiles_batch

    def unexpected_post(*args, **kwargs):
        pytest.fail('Invalid recipient lists must not reach LiquidFiles')

    monkeypatch.setattr('app.requests.Session.post', unexpected_post)
    response = client.post(f'/send-liquidfiles/{session_id}', json={'recipients': recipients})
    assert response.status_code == 400


def test_liquidfiles_disallows_anonymous_sender(liquidfiles_batch, monkeypatch):
    client, session_id, _ = liquidfiles_batch
    monkeypatch.setattr('app.AZURE_CLIENT_ID', '')
    monkeypatch.setattr('app.AZURE_TENANT_ID', '')
    response = client.post(f'/send-liquidfiles/{session_id}', json={'email': 'recipient@example.com'})
    assert response.status_code == 401


def test_liquidfiles_streams_single_file_without_zip(liquidfiles_batch, monkeypatch):
    client, session_id, output_root = liquidfiles_batch
    for path in (output_root / session_id).rglob('*.dcm'):
        if path.name != 'first.dcm':
            path.unlink()
    calls = []

    def post(api_client, url, **kwargs):
        calls.append(url)
        if url.endswith('/upload'):
            assert kwargs['params']['filename'] == 'first.dcm'
            assert kwargs['headers']['Content-Type'] == 'application/octet-stream'
            assert kwargs['data'].read() == b'first scan'
            return Mock(json=Mock(return_value={'attachment': {'id': 'single-file'}}))
        assert 'sender' not in kwargs['json']['message']
        assert kwargs['json']['message']['attachments'] == ['single-file']
        return Mock(json=Mock(return_value={'message': {'id': 'sent'}}))

    monkeypatch.setattr('app.requests.Session.post', post)
    response = client.post(f'/send-liquidfiles/{session_id}', json={'recipients': ['user@example.com']})
    assert response.status_code == 200
    assert len(calls) == 2
    assert not list(output_root.glob('*.zip'))
