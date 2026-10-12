import os
import subprocess
import sys
import zipfile

import py7zr
import pytest
import rarfile

from app import ArchiveValidationError, _extract_archive, _validate_archive_entries


def test_extract_archive_supports_7z(tmp_path, monkeypatch):
    def make_test_directory(path):
        path.mkdir(parents=True, exist_ok=True)
        return True

    monkeypatch.setattr("app.safe_makedirs", make_test_directory)

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    dicom_file = source_dir / "scan.dcm"
    dicom_file.write_bytes(b"DICOM test payload")
    archive_path = tmp_path / "study.7z"

    with py7zr.SevenZipFile(archive_path, mode="w") as archive:
        archive.write(dicom_file, arcname="study/scan.dcm")

    extract_dir = tmp_path / "extracted"
    assert _extract_archive(archive_path, extract_dir) is True
    assert (extract_dir / "study" / "scan.dcm").read_bytes() == b"DICOM test payload"


def test_extract_archive_preserves_zip_support(tmp_path, monkeypatch):
    def make_test_directory(path):
        path.mkdir(parents=True, exist_ok=True)
        return True

    monkeypatch.setattr("app.safe_makedirs", make_test_directory)
    archive_path = tmp_path / "study.zip"
    with zipfile.ZipFile(archive_path, mode="w") as archive:
        archive.writestr("study/scan.dcm", b"DICOM test payload")

    extract_dir = tmp_path / "extracted"
    assert _extract_archive(archive_path, extract_dir) is True
    assert (extract_dir / "study" / "scan.dcm").read_bytes() == b"DICOM test payload"


def test_extract_archive_supports_rar(tmp_path, monkeypatch):
    class ArchiveEntry:
        filename = "study/scan.dcm"
        file_size = 18

        @staticmethod
        def is_symlink():
            return False

    class RarArchive:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        @staticmethod
        def needs_password():
            return False

        @staticmethod
        def infolist():
            return [ArchiveEntry()]

        @staticmethod
        def extractall(path):
            output = path / "study" / "scan.dcm"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"DICOM test payload")

    def make_test_directory(path):
        path.mkdir(parents=True, exist_ok=True)
        return True

    monkeypatch.setattr("app.safe_makedirs", make_test_directory)
    monkeypatch.setattr(rarfile, "RarFile", RarArchive)
    archive_path = tmp_path / "study.rar"
    archive_path.touch()

    extract_dir = tmp_path / "extracted"
    assert _extract_archive(archive_path, extract_dir) is True
    assert (extract_dir / "study" / "scan.dcm").read_bytes() == b"DICOM test payload"


def test_archive_entries_reject_path_traversal():
    with pytest.raises(ArchiveValidationError, match="invalid paths"):
        _validate_archive_entries([("../outside.dcm", 10)])


def test_limits_can_be_configured_from_environment():
    result = subprocess.run(
        [sys.executable, "-c", (
            "import app\n"
            "assert app.app.config['MAX_CONTENT_LENGTH'] == 10_000_000_000\n"
            "assert app.MAX_ARCHIVE_EXTRACTED_SIZE == 2_500_000_000\n"
            "assert app.MAX_ARCHIVE_ENTRIES == 2\n"
            "app._validate_archive_entries([('scan.dcm', 2_500_000_000)])\n"
            "for entries, message in [\n"
            "    ([('scan.dcm', 2_500_000_001)], 'Archive is too large when extracted'),\n"
            "    ([('scan.dcm', 0)] * 3, 'Archive contains too many entries'),\n"
            "]:\n"
            "    try:\n"
            "        app._validate_archive_entries(entries)\n"
            "    except app.ArchiveValidationError as exc:\n"
            "        assert message in str(exc)\n"
            "        assert exc.status_code == 413\n"
            "    else:\n"
            "        raise AssertionError('Configured archive limit was not enforced')\n"
        )],
        env={
            **os.environ,
            "MAX_CONTENT_LENGTH_GB": "10",
            "MAX_ARCHIVE_EXTRACTED_SIZE_GB": "2.5",
            "MAX_ARCHIVE_ENTRIES": "2",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr