import os
import io
import zipfile

import pytest

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
