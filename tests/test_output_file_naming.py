import os

from app import _ensure_dicom_filename, _compute_unique_dicom_rel_path


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
