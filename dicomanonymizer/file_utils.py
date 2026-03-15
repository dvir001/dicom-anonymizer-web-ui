import os
from typing import Optional, Set


def _extract_base_filename(filename: str) -> str:
    """Return a safe base name to use when converting to .dcm."""
    if not filename:
        return 'dicom_file'

    base, ext = os.path.splitext(filename)
    # Python's splitext treats dotfiles (e.g. '.dcm') as having no extension,
    # returning ('.dcm', ''). In that case the file has no meaningful base name,
    # so clear it to trigger the 'dicom_file' fallback below.
    if not ext and base.startswith('.'):
        base = ''
    sanitized = base.strip().strip('.')
    return sanitized or 'dicom_file'


def _ensure_dicom_filename(filename: str) -> str:
    """Force a filename to use the .dcm extension while preserving the base name."""
    base_name = _extract_base_filename(filename)
    return f"{base_name}.dcm"


def _compute_unique_dicom_rel_path(rel_path: str, used_paths: Optional[Set[str]] = None) -> str:
    """Convert a relative path to use .dcm extension and avoid duplicates within a session."""
    if used_paths is None:
        used_paths = set()

    normalized_rel = rel_path.replace('/', os.sep).replace('\\', os.sep)
    rel_dir, original_name = os.path.split(normalized_rel)
    candidate_name = _ensure_dicom_filename(original_name)
    candidate_rel = os.path.join(rel_dir, candidate_name) if rel_dir else candidate_name
    normalized_candidate = os.path.normpath(candidate_rel)

    base_name = _extract_base_filename(original_name)
    suffix = 1
    while normalized_candidate in used_paths:
        alt_name = _ensure_dicom_filename(f"{base_name}-{suffix}")
        candidate_rel = os.path.join(rel_dir, alt_name) if rel_dir else alt_name
        normalized_candidate = os.path.normpath(candidate_rel)
        suffix += 1

    used_paths.add(normalized_candidate)
    return normalized_candidate
