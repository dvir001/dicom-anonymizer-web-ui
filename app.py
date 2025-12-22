# Flask DICOM Anonymizer Web Application
"""
A secure web-based DICOM file anonymizer that provides both minimal and standard anonymization modes.
Features include file validation, automatic cleanup, session management, and secure authentication.
"""

import os
import tempfile
import shutil
import threading
import time
import datetime
import hashlib
import logging
import secrets
import re
import posixpath
from typing import Optional, List, Set
from flask import Flask, render_template, request, send_file, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import zipfile
from dicomanonymizer.simpledicomanonymizer import anonymize_dicom_file
from dicomanonymizer.anonymizer import isDICOMType
from pydicom import dcmread
from pydicom.errors import InvalidDicomError
import json
import traceback
from functools import wraps
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

_default_log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=_default_log_level,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )
logger = logging.getLogger(__name__)
security_logger = logging.getLogger(f"{__name__}.security")

# Resolve root directory
PROJECT_ROOT = Path(os.getenv('DICOM_APP_ROOT', Path.cwd()))

# Flask application configuration
app = Flask(__name__)
_secret_key = os.getenv('SECRET_KEY')
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    logger.warning("SECRET_KEY is not set; generated ephemeral secret key for this process")
elif len(_secret_key) < 32:
    logger.warning("SECRET_KEY is shorter than 32 characters; consider using a 64-character random string")

app.config['SECRET_KEY'] = _secret_key
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024 * 1024  # 3GB max file size

# Configure proxy support for proper HTTPS detection behind reverse proxies
# This enables the app to trust X-Forwarded-* headers from nginx
app.wsgi_app = ProxyFix(
    app.wsgi_app, 
    x_for=1,      # Trust X-Forwarded-For
    x_proto=1,    # Trust X-Forwarded-Proto (for HTTPS detection)
    x_host=1,     # Trust X-Forwarded-Host
    x_prefix=1    # Trust X-Forwarded-Prefix
)

_allowed_origins = [origin.strip() for origin in os.getenv('CORS_ALLOWED_ORIGINS', '').split(',') if origin.strip()]
if _allowed_origins:
    CORS(app, resources={r"/api/*": {"origins": _allowed_origins}})
    logger.info("Configured CORS for origins: %s", _allowed_origins)

# Environment detection
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
IS_PRODUCTION = FLASK_ENV.lower() == 'production'

# Security and session configuration
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
if not ADMIN_PASSWORD:
    if IS_PRODUCTION:
        raise RuntimeError('ADMIN_PASSWORD must be set in production environments')
    ADMIN_PASSWORD = 'admin123'
    security_logger.warning('ADMIN_PASSWORD not set; using development fallback password')
elif ADMIN_PASSWORD == 'admin123':
    security_logger.warning('ADMIN_PASSWORD uses insecure default value; update ADMIN_PASSWORD for better security')
SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', '60'))

# Application startup logging
logger.info("DICOM Anonymizer - Environment: %s", FLASK_ENV)
logger.info("Authentication enabled - Session timeout: %s minutes", SESSION_TIMEOUT_MINUTES)


# Directory setup for file operations
UPLOAD_FOLDER = PROJECT_ROOT / 'temp_uploads'
OUTPUT_FOLDER = PROJECT_ROOT / 'temp_outputs'

try:
    UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    logger.info("Working directories initialized: uploads=%s, outputs=%s", UPLOAD_FOLDER, OUTPUT_FOLDER)
except PermissionError as e:
    logger.error("Permission error creating directories: %s", e)
    # Fallback to system temp directory
    UPLOAD_FOLDER = Path(tempfile.mkdtemp(prefix='dicom_uploads_'))
    OUTPUT_FOLDER = Path(tempfile.mkdtemp(prefix='dicom_outputs_'))
    logger.warning("Using fallback directories: uploads=%s, outputs=%s", UPLOAD_FOLDER, OUTPUT_FOLDER)

app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['OUTPUT_FOLDER'] = str(OUTPUT_FOLDER)

# Session tracking for automatic cleanup (10 minutes)
session_timestamps = {}
session_metadata = {}
user_session_counts = {}
session_lock = threading.Lock()

# Storage management configuration
MAX_TOTAL_STORAGE = 20 * 1024 * 1024 * 1024  # 20GB total storage limit
SESSION_TIMEOUT_MINUTES_FILE = int(os.getenv('SESSION_FILE_TIMEOUT_MINUTES', '30'))
MAX_SESSIONS_PER_USER = int(os.getenv('MAX_SESSIONS_PER_USER', '3'))

# Global cache for consistent name mappings during anonymization
name_mapping_cache = {}

# Download packaging configuration (favor speed over compression by default)
ZIP_COMPRESSION_MODE = os.getenv('ZIP_COMPRESSION_MODE', 'stored').lower()
if ZIP_COMPRESSION_MODE == 'deflated':
    ZIP_COMPRESSION = zipfile.ZIP_DEFLATED
    try:
        ZIP_COMPRESSLEVEL = int(os.getenv('ZIP_COMPRESSLEVEL', '4'))
    except ValueError:
        ZIP_COMPRESSLEVEL = 4
else:
    ZIP_COMPRESSION = zipfile.ZIP_STORED
    ZIP_COMPRESSLEVEL = None


def _get_directory_size(path: str) -> int:
    total_size = 0
    for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            try:
                total_size += os.path.getsize(file_path)
            except OSError:
                continue
    return total_size


def _extract_base_filename(filename: str) -> str:
    """Return a safe base name to use when converting to .dcm."""
    if not filename:
        return 'dicom_file'

    base, _ = os.path.splitext(filename)
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


def _register_session_dicom_paths(session_id: str, new_paths: Optional[List[str]] = None) -> int:
    """Track DICOM file paths for a session and return the updated count."""
    if new_paths is None:
        new_paths = []

    with session_lock:
        metadata = session_metadata.get(session_id, {}).copy()
        dicom_paths = metadata.get('dicom_paths')

        if isinstance(dicom_paths, set):
            tracked = dicom_paths
        elif isinstance(dicom_paths, list):
            tracked = set(dicom_paths)
        else:
            tracked = set()

        if new_paths:
            tracked.update(path for path in new_paths if path)

        metadata['dicom_paths'] = tracked
        metadata['dicom_count'] = len(tracked)
        session_metadata[session_id] = metadata

        return metadata['dicom_count']


def _get_tracked_dicom_paths(session_id: str) -> Set[str]:
    """Return a copy of tracked DICOM paths for a session."""
    with session_lock:
        metadata = session_metadata.get(session_id, {})
        dicom_paths = metadata.get('dicom_paths')

        if isinstance(dicom_paths, set):
            tracked = set(dicom_paths)
        elif isinstance(dicom_paths, list):
            tracked = set(dicom_paths)
            metadata = metadata.copy()
            metadata['dicom_paths'] = tracked
            metadata['dicom_count'] = len(tracked)
            session_metadata[session_id] = metadata
        else:
            tracked = set()
            metadata = metadata.copy()
            metadata['dicom_paths'] = tracked
            metadata['dicom_count'] = 0
            session_metadata[session_id] = metadata

        return tracked


def _get_total_storage_usage() -> int:
    total = 0
    for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
        if os.path.exists(folder):
            total += _get_directory_size(str(folder))
    return total


def _record_session_activity(session_id: str, session_size: int = 0, fingerprint: Optional[str] = None) -> None:
    with session_lock:
        now = time.time()
        session_timestamps[session_id] = now
        metadata = session_metadata.get(session_id, {}).copy()
        if not metadata:
            metadata = {'created': now, 'last_size': 0, 'fingerprint': fingerprint, 'dicom_paths': set(), 'dicom_count': 0}
        else:
            metadata.setdefault('created', now)
            if fingerprint:
                metadata['fingerprint'] = fingerprint

        dicom_paths = metadata.get('dicom_paths')
        if isinstance(dicom_paths, list):
            dicom_paths = set(dicom_paths)
        elif dicom_paths is None:
            dicom_paths = set()
        metadata['dicom_paths'] = dicom_paths
        metadata['dicom_count'] = len(dicom_paths)

        if session_size >= 0:
            metadata['last_size'] = session_size

        session_metadata[session_id] = metadata


def _clear_session_activity(session_id: str) -> None:
    with session_lock:
        session_timestamps.pop(session_id, None)
        metadata = session_metadata.pop(session_id, None)
        if metadata:
            fingerprint = metadata.get('fingerprint')
            if fingerprint and fingerprint in user_session_counts:
                user_session_counts[fingerprint] = max(0, user_session_counts[fingerprint] - 1)
                if user_session_counts[fingerprint] == 0:
                    user_session_counts.pop(fingerprint, None)


def _active_session_count() -> int:
    with session_lock:
        return len(session_timestamps)


def secure_url_for(endpoint, **values):
    """
    Generate URLs with proper HTTPS detection for reverse proxy environments.
    This function ensures redirects use the correct protocol (HTTP/HTTPS)
    by checking the X-Forwarded-Proto header.
    """
    # Check if we're behind a proxy with HTTPS
    if request.headers.get('X-Forwarded-Proto') == 'https':
        # Force HTTPS scheme for URL generation
        return url_for(endpoint, _external=True, _scheme='https', **values)
    elif request.headers.get('X-Forwarded-Proto') == 'http':
        # Force HTTP scheme for URL generation
        return url_for(endpoint, _external=True, _scheme='http', **values)
    else:
        # Fallback to default behavior (useful for local development)
        return url_for(endpoint, **values)


# Brute force protection - tracks failed login attempts by client fingerprint
login_attempts_global = {}

# Brute force protection configuration  
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
LOGIN_LOCKOUT_DURATION = int(os.getenv('LOGIN_LOCKOUT_DURATION', '300'))  # 5 minutes default
EXPONENTIAL_BACKOFF_BASE = int(os.getenv('EXPONENTIAL_BACKOFF_BASE', '2'))  # seconds


def get_client_fingerprint(request):
    """
    Generate a client fingerprint using user agent and other headers.
    This provides basic client identification without relying on IP addresses.
    """
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    # Create a fingerprint from headers
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
    fingerprint_hash = hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()[:16]
    
    return fingerprint_hash


def is_client_locked_out(client_fingerprint):
    """
    Check if a client is currently locked out due to too many failed attempts.
    Returns (is_locked_out, remaining_lockout_seconds)
    """
    if client_fingerprint not in login_attempts_global:
        return False, 0
    
    attempts, lockout_start_time = login_attempts_global[client_fingerprint]
    
    # If haven't reached max attempts yet, not locked out
    if attempts < MAX_LOGIN_ATTEMPTS:
        return False, 0
    
    # Check if lockout duration has passed
    current_time = time.time()
    time_since_lockout = current_time - lockout_start_time
    
    if time_since_lockout < LOGIN_LOCKOUT_DURATION:
        remaining_lockout = LOGIN_LOCKOUT_DURATION - time_since_lockout
        return True, remaining_lockout
    else:
        # Lockout duration has passed, reset attempts
        del login_attempts_global[client_fingerprint]
        return False, 0


def record_failed_login_attempt(client_fingerprint):
    """
    Record a failed login attempt for the client fingerprint.
    Returns (current_attempts, is_now_locked_out)
    """
    current_time = time.time()
    
    if client_fingerprint not in login_attempts_global:
        # First failed attempt
        login_attempts_global[client_fingerprint] = (1, current_time)
        security_logger.warning(
            "First failed login attempt for fingerprint %s",
            client_fingerprint[:8]
        )
        return 1, False
    else:
        attempts, first_attempt_time = login_attempts_global[client_fingerprint]
        
        # Increment attempt count but keep original timestamp for proper lockout tracking
        new_attempts = attempts + 1
        login_attempts_global[client_fingerprint] = (new_attempts, first_attempt_time)
        
        # Check if this triggers a lockout
        is_locked_out = new_attempts >= MAX_LOGIN_ATTEMPTS
        
        security_logger.warning(
            "Failed login attempt #%s for fingerprint %s",
            new_attempts,
            client_fingerprint[:8]
        )
        if is_locked_out:
            security_logger.error(
                "Client fingerprint %s locked out after %s attempts",
                client_fingerprint[:8],
                new_attempts
            )
        
        return new_attempts, is_locked_out


def clear_failed_login_attempts(client_fingerprint):
    """
    Clear failed login attempts for a client fingerprint after successful login.
    """
    if client_fingerprint in login_attempts_global:
        attempts, _ = login_attempts_global[client_fingerprint]
        del login_attempts_global[client_fingerprint]
        security_logger.info(
            "Cleared %s failed login attempts for fingerprint %s",
            attempts,
            client_fingerprint[:8]
        )


def calculate_backoff_delay(attempts):
    """
    Calculate exponential backoff delay based on number of attempts.
    """
    # Cap the backoff to prevent extremely long delays
    max_attempts_for_backoff = 6
    capped_attempts = min(attempts, max_attempts_for_backoff)
    
    # Exponential backoff: 2^attempts seconds, capped at 32 seconds
    delay = min(EXPONENTIAL_BACKOFF_BASE ** capped_attempts, 32)
    return delay


def _request_wants_json() -> bool:
    """Determine whether the current request expects a JSON response."""
    if request.is_json:
        return True

    accept = request.headers.get('Accept', '')
    if 'application/json' in accept.lower():
        return True

    requested_with = request.headers.get('X-Requested-With', '').lower()
    if requested_with == 'xmlhttprequest':
        return True

    return request.path.startswith('/api/')


def _current_session_state():
    """Return tuple (is_valid, reason, remaining_seconds) for the current session."""
    authenticated = session.get('authenticated')
    login_time = session.get('login_time')

    if not authenticated or not login_time:
        return False, 'not_authenticated', 0

    max_age = SESSION_TIMEOUT_MINUTES * 60
    current_time = time.time()
    session_age = current_time - login_time

    if session_age > max_age:
        return False, 'expired', 0

    if authenticated is not True:
        return False, 'invalid_marker', 0

    remaining_seconds = max(int(max_age - session_age), 0)
    return True, 'active', remaining_seconds


def allowed_file(filename):
    """Enhanced file validation that tolerates browser-relative paths."""
    if not filename:
        return False

    # Browsers may send folder uploads as relative paths; only validate the basename.
    filename = os.path.basename(filename).lower()

    dangerous_extensions = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
        '.sh', '.py', '.pl', '.php', '.asp', '.aspx', '.jsp', '.ps1', '.psm1'
    }

    for ext in dangerous_extensions:
        if filename.endswith(ext):
            logger.warning("Blocked upload of potentially dangerous file: %s", filename)
            return False

    parts = filename.split('.')
    if len(parts) > 2:
        for part in parts[1:-1]:
            if f'.{part}' in dangerous_extensions:
                logger.warning("Blocked upload of file with dangerous hidden extension: %s", filename)
                return False

    if '\x00' in filename or '..' in filename or '/' in filename or '\\' in filename:
        logger.warning("Blocked upload of file with dangerous characters: %s", filename)
        return False

    return True


def is_dicom_file(filepath):
    """Check if file is a DICOM file using layered content-based validation."""
    if not filepath or not os.path.exists(filepath) or not os.path.isfile(filepath):
        return False

    try:
        if isDICOMType(filepath):
            return True
    except Exception:
        logger.debug("isDICOMType check failed for %s", filepath, exc_info=True)

    try:
        with open(filepath, 'rb') as stream:
            preamble = stream.read(132)
            if len(preamble) >= 132 and preamble[128:132] == b'DICM':
                return True
    except OSError:
        return False

    try:
        dcmread(filepath, stop_before_pixels=True, force=True)
        return True
    except InvalidDicomError:
        pass
    except Exception:
        logger.exception("Unexpected error while probing DICOM file: %s", filepath)

    try:
        return isDICOMType(filepath)
    except Exception:
        return False


def safe_makedirs(path):
    """Safely create directories with comprehensive error handling and validation."""
    try:
        normalized_path = os.path.normpath(path)

        if normalized_path.startswith('..'):
            logger.error("Attempted path traversal in directory creation: %s", path)
            return False

        abs_path = os.path.abspath(normalized_path)
        norm_abs_path = os.path.normcase(abs_path)
        normalized_bases = [
            os.path.normcase(os.path.abspath(str(UPLOAD_FOLDER))),
            os.path.normcase(os.path.abspath(str(OUTPUT_FOLDER))),
            os.path.normcase(os.path.abspath(tempfile.gettempdir()))
        ]

        try:
            base_allowed = any(
                os.path.commonpath([norm_abs_path, base]) == base
                for base in normalized_bases
            )
        except ValueError:
            base_allowed = False

        if not base_allowed:
            logger.error("Path outside allowed directories: %s", abs_path)
            return False

        os.makedirs(abs_path, exist_ok=True)
        return True
    except PermissionError as e:
        logger.error("Permission error creating directory %s: %s", path, e)
        return False
    except Exception as e:
        logger.exception("Unexpected error creating directory %s", path)
        return False


def _sanitize_relative_path(raw_path: str) -> tuple[str, str]:
    """Sanitize and split a relative path into directory and filename components."""
    if not raw_path:
        return '', ''

    cleaned = raw_path.replace('\\', '/').strip()
    if not cleaned:
        return '', ''

    cleaned = cleaned.lstrip('/')
    normalized = posixpath.normpath(cleaned)
    if normalized in ('', '.', '..') or normalized.startswith('../'):
        return '', ''

    parts = [part for part in normalized.split('/') if part not in ('', '.', '..')]
    if not parts:
        return '', ''

    sanitized_parts = [secure_filename(part) for part in parts]
    sanitized_parts = [part for part in sanitized_parts if part]
    if not sanitized_parts:
        return '', ''

    if len(sanitized_parts) == 1:
        return '', sanitized_parts[0]

    directory = os.path.join(*sanitized_parts[:-1])
    filename = sanitized_parts[-1]
    return directory, filename


def _serialize_session_state(session_id: str) -> Optional[dict]:
    """Build a client-safe representation of an upload session."""
    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    if not os.path.exists(session_dir):
        return None

    tracked_dicom_paths = _get_tracked_dicom_paths(session_id)
    working_dicom_paths = set(tracked_dicom_paths)
    new_tracked_paths: List[str] = []

    files: list[dict] = []
    for root, _, filenames in os.walk(session_dir):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            if not os.path.isfile(file_path):
                continue

            rel_path = os.path.relpath(file_path, session_dir).replace('\\', '/')
            from_zip = rel_path.startswith('extracted_')
            original_archive = None

            if from_zip:
                first_segment = rel_path.split('/', 1)[0]
                original_archive = first_segment.replace('extracted_', '')

            is_dicom = rel_path in working_dicom_paths
            if not is_dicom:
                is_dicom = is_dicom_file(file_path)
                if is_dicom:
                    working_dicom_paths.add(rel_path)
                    new_tracked_paths.append(rel_path)

            files.append({
                'name': filename,
                'relative_path': rel_path,
                'is_dicom': is_dicom,
                'from_zip': from_zip,
                'original_archive': original_archive,
            })

    files.sort(key=lambda item: item['relative_path'])

    if new_tracked_paths:
        _register_session_dicom_paths(session_id, new_tracked_paths)

    total_dicom = len(working_dicom_paths)

    metadata = session_metadata.get(session_id, {})
    created_ts = metadata.get('created')
    created_iso = None
    expires_in_seconds = None

    if created_ts:
        created_iso = datetime.datetime.fromtimestamp(created_ts).isoformat()
        age_seconds = max(time.time() - created_ts, 0)
        expires_in_seconds = max(int(SESSION_TIMEOUT_MINUTES_FILE * 60 - age_seconds), 0)

    return {
        'session_id': session_id,
        'files': files,
        'total_dicom_count': total_dicom,
        'created': created_iso,
        'expires_in_seconds': expires_in_seconds
    }


def get_consistent_random_number(name):
    """
    Generate a consistent random number for a given name using SHA-256 hash.
    This ensures the same name always gets the same anonymized value.
    """
    if name in name_mapping_cache:
        return name_mapping_cache[name]
    
    # Create a hash of the name and convert to a consistent number
    hash_obj = hashlib.sha256(name.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    # Take first 8 characters and convert to int, get last 6 digits
    random_number = str(int(hash_hex[:8], 16))[-6:]
    
    name_mapping_cache[name] = random_number
    return random_number


def create_minimal_anonymization_rules():
    """
    Create custom anonymization rules for minimal anonymization mode.
    Only anonymizes patient names, Patient ID, and Study ID while preserving all other data.
    """
    def anonymize_name(dataset, tag):
        """Replace names with consistent random numbers."""
        element = dataset.get(tag)
        if element is not None and element.value:
            original_name = str(element.value)
            random_number = get_consistent_random_number(original_name)
            element.value = random_number
    
    def anonymize_procedure(dataset, tag):
        """Replace procedure descriptions with 'ANONYMIZED'."""
        element = dataset.get(tag)
        if element is not None:
            element.value = "ANONYMIZED"
    
    def anonymize_patient_id(dataset, tag):
        """Replace Patient ID with same random number as Patient's Name for consistency."""
        element = dataset.get(tag)
        if element is not None and element.value:
            # Get Patient's Name to generate consistent ID
            patient_name_element = dataset.get((0x0010, 0x0010))
            if patient_name_element and patient_name_element.value:
                # Use the patient's name to generate consistent ID
                original_name = str(patient_name_element.value)
                random_number = get_consistent_random_number(original_name)
                element.value = random_number
            else:
                # Fallback: use the current ID value to generate random number
                original_id = str(element.value)
                random_number = get_consistent_random_number(original_id)
                element.value = random_number
    
    def anonymize_study_id(dataset, tag):
        """Replace Study ID with 'ANONYMIZED'."""
        element = dataset.get(tag)
        if element is not None:
            element.value = "ANONYMIZED"
    
    # Define the minimal rules - only for names, Patient ID, and Study ID
    minimal_rules = {
        (0x0010, 0x0010): anonymize_name,  # Patient's Name
        (0x0010, 0x0020): anonymize_patient_id,  # Patient ID (match Patient's Name)
        (0x0020, 0x0010): anonymize_study_id,  # Study ID
    }
    
    return minimal_rules


def cleanup_non_dicom_files(uploaded_files, session_dir):
    """
    Immediately delete non-DICOM files to save storage space and improve security.
    Returns the number of files deleted.
    """
    files_deleted = 0
    for file_info in uploaded_files:
        if not file_info['is_dicom']:
            try:
                file_path = file_info['path']
                if os.path.exists(file_path):
                    os.remove(file_path)
                    files_deleted += 1
            except Exception as e:
                logger.exception("Error deleting non-DICOM file %s", file_info['name'])
    
    # Clean up empty extraction directories
    try:
        extract_dir = os.path.join(session_dir, 'extracted')
        if os.path.exists(extract_dir):
            # Check if extract_dir only contains non-DICOM files
            remaining_dicom_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    if is_dicom_file(full_path):
                        remaining_dicom_files.append(full_path)
            
            # If no DICOM files remain in extracted directory, remove it
            if not remaining_dicom_files:
                shutil.rmtree(extract_dir)
    except Exception as e:
        logger.exception("Error cleaning up extraction directory")
    
    return files_deleted


def cleanup_old_sessions():
    """
    Background task to automatically clean up sessions older than 10 minutes.
    Runs continuously to prevent storage accumulation.
    """
    while True:
        try:
            current_time = time.time()
            with session_lock:
                sessions_snapshot = list(session_timestamps.items())

            timeout_seconds = SESSION_TIMEOUT_MINUTES_FILE * 60
            sessions_to_remove = [
                session_id for session_id, timestamp in sessions_snapshot
                if current_time - timestamp > timeout_seconds
            ]
            
            # Clean up old sessions
            for session_id in sessions_to_remove:
                try:
                    # Clean up upload session
                    upload_session = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
                    if os.path.exists(upload_session):
                        shutil.rmtree(upload_session)
                    
                    # Clean up output session
                    output_session = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
                    if os.path.exists(output_session):
                        shutil.rmtree(output_session)
                    
                    # Clean up zip files
                    zip_file = os.path.join(app.config['OUTPUT_FOLDER'], f'{session_id}_anonymized.zip')
                    if os.path.exists(zip_file):
                        os.remove(zip_file)
                    
                    # Remove from tracking
                    _clear_session_activity(session_id)
                    
                except Exception as e:
                    logger.exception("Error cleaning up session %s", session_id)
            
            # Sleep for 1 minute before next cleanup check
            time.sleep(60)
            
        except Exception as e:
            logger.exception("Error in cleanup thread")
            time.sleep(60)  # Continue checking even if there's an error


def login_required(f):
    """
    Decorator to enforce authentication on protected routes.
    Validates session authentication and handles timeouts.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_valid, reason, _ = _current_session_state()

        if not is_valid:
            session.clear()
            if reason == 'expired':
                flash('Session expired. Please login again.', 'info')
                message = 'Session expired. Please login again.'
            else:
                flash('Please login to continue.', 'warning')
                message = 'Authentication required.'

            if _request_wants_json():
                return jsonify({'error': message, 'reason': reason}), 401

            return redirect(secure_url_for('index'))

        return f(*args, **kwargs)
    return decorated_function


# Start the cleanup background thread
cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
cleanup_thread.start()


@app.route('/health')
def health_check():
    """Health check endpoint for container monitoring and load balancer checks."""
    try:
        # Basic health checks
        checks = {
            'upload_folder_exists': os.path.exists(app.config['UPLOAD_FOLDER']),
            'output_folder_exists': os.path.exists(app.config['OUTPUT_FOLDER']),
            'upload_folder_writable': os.access(app.config['UPLOAD_FOLDER'], os.W_OK),
            'output_folder_writable': os.access(app.config['OUTPUT_FOLDER'], os.W_OK),
            'environment': os.getenv('FLASK_ENV', 'development'),
            'active_sessions': _active_session_count()
        }
        
        # Check if all critical components are healthy
        all_healthy = all([
            checks['upload_folder_exists'],
            checks['output_folder_exists'],
            checks['upload_folder_writable'],
            checks['output_folder_writable']
        ])
        
        if all_healthy:
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'checks': checks
            }), 200
        else:
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'checks': checks
            }), 503
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


@app.route('/')
def index():
    """Main application page with inline authentication modal."""
    is_authenticated, _, remaining_seconds = _current_session_state()

    if not is_authenticated:
        session.clear()

    existing_sessions: list[dict] = []

    if is_authenticated:
        user_sessions = session.get('user_sessions', [])
        valid_sessions = []

        for session_id in user_sessions:
            serialized = _serialize_session_state(session_id)
            if serialized is None:
                _clear_session_activity(session_id)
                continue

            existing_sessions.append(serialized)
            valid_sessions.append(session_id)

        if valid_sessions != user_sessions:
            session['user_sessions'] = valid_sessions

        existing_sessions.sort(key=lambda item: item.get('created') or '')

    return render_template(
        'index.html',
        is_authenticated=is_authenticated,
        session_timeout_minutes=SESSION_TIMEOUT_MINUTES,
        session_remaining_seconds=remaining_seconds,
        login_lockout_duration=LOGIN_LOCKOUT_DURATION,
        max_login_attempts=MAX_LOGIN_ATTEMPTS,
        existing_sessions=existing_sessions
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authentication endpoint with brute force protection and JSON support."""
    if request.method == 'GET':
        is_authenticated, _, _ = _current_session_state()

        if _request_wants_json():
            return jsonify({'authenticated': is_authenticated}), 200

        return redirect(secure_url_for('index'))

    payload = request.get_json(silent=True) or request.form
    password = (payload.get('password') or '').strip()

    client_fingerprint = get_client_fingerprint(request)

    if session.get('authenticated'):
        security_logger.info(
            "Login attempt while already authenticated for fingerprint %s",
            client_fingerprint[:8]
        )
        if _request_wants_json():
            return jsonify({'success': True, 'already_authenticated': True}), 200
        return redirect(request.args.get('next') or secure_url_for('index'))

    is_locked_out, remaining_lockout = is_client_locked_out(client_fingerprint)
    if is_locked_out:
        minutes, seconds = divmod(int(max(remaining_lockout, 0)), 60)
        message = (
            f'Too many failed login attempts. Try again in {int(minutes)} minute(s) '
            f'and {int(seconds)} second(s).'
        )
        security_logger.error(
            "Login attempt blocked for fingerprint %s; locked out for %ss",
            client_fingerprint[:8],
            int(remaining_lockout)
        )
        if _request_wants_json():
            return jsonify({
                'success': False,
                'error': message,
                'locked_out': True,
                'retry_after': int(remaining_lockout)
            }), 403

        flash(message, 'danger')
        return redirect(secure_url_for('index'))

    if password == ADMIN_PASSWORD:
        clear_failed_login_attempts(client_fingerprint)

        session.clear()
        session['authenticated'] = True
        session['login_time'] = time.time()
        session.permanent = True
        app.permanent_session_lifetime = datetime.timedelta(minutes=SESSION_TIMEOUT_MINUTES)

        security_logger.info(
            "Successful authentication for fingerprint %s",
            client_fingerprint[:8]
        )

        if _request_wants_json():
            return jsonify({'success': True}), 200

        flash('Login successful!', 'success')
        return redirect(request.args.get('next') or secure_url_for('index'))

    attempts, is_now_locked_out = record_failed_login_attempt(client_fingerprint)

    backoff_delay = calculate_backoff_delay(attempts)
    security_logger.warning(
        "Applying %ss backoff for fingerprint %s (attempt #%s)",
        backoff_delay,
        client_fingerprint[:8],
        attempts
    )
    time.sleep(backoff_delay)

    if is_now_locked_out:
        message = (
            f'Too many failed login attempts. Access temporarily restricted for '
            f'{LOGIN_LOCKOUT_DURATION // 60} minutes.'
        )
        if _request_wants_json():
            return jsonify({
                'success': False,
                'error': message,
                'locked_out': True,
                'retry_after': LOGIN_LOCKOUT_DURATION
            }), 403

        flash(message, 'danger')
        return redirect(secure_url_for('index'))

    remaining_attempts = max(MAX_LOGIN_ATTEMPTS - attempts, 0)
    message = f'Invalid password. {remaining_attempts} attempt(s) remaining.'

    if _request_wants_json():
        return jsonify({
            'success': False,
            'error': message,
            'locked_out': False,
            'attempts_remaining': remaining_attempts
        }), 401

    flash(message, 'danger')
    return redirect(secure_url_for('index'))


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    """User logout endpoint with session cleanup."""
    user_sessions = session.get('user_sessions', [])

    for tracked_session in user_sessions:
        try:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], tracked_session)
            output_dir = os.path.join(app.config['OUTPUT_FOLDER'], tracked_session)

            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir)
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

            _clear_session_activity(tracked_session)
        except Exception:
            logger.exception("Error cleaning up user session %s on logout", tracked_session)

    session.clear()

    if _request_wants_json():
        return jsonify({'success': True}), 200

    flash('You have been logged out.', 'info')
    return redirect(secure_url_for('index'))


@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    """
    Handle file uploads with DICOM validation and ZIP extraction.
    Enhanced with size validation, storage checks, and secure folder support.
    """
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400

    client_fingerprint = get_client_fingerprint(request)

    total_upload_size = 0
    for storage_file in files:
        if storage_file and hasattr(storage_file, 'content_length') and storage_file.content_length:
            total_upload_size += storage_file.content_length
        elif storage_file:
            try:
                stream = storage_file.stream
                current_pos = stream.tell()
                stream.seek(0, os.SEEK_END)
                total_upload_size += stream.tell()
                stream.seek(current_pos)
            except (OSError, AttributeError):
                pass

    if total_upload_size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({
            'error': f'Upload size ({total_upload_size // (1024 * 1024)} MB) exceeds session limit (3GB)'
        }), 413

    current_storage = _get_total_storage_usage()
    if current_storage + total_upload_size > MAX_TOTAL_STORAGE * 0.9:
        return jsonify({
            'error': 'Server storage nearly full. Please try again later or contact administrator.'
        }), 507
    
    # Get existing session ID or create new one
    session_id = request.form.get('session_id')
    is_new_session = False
    
    if session_id:
        if not re.match(r'^[a-f0-9]{32}$', session_id):
            return jsonify({'error': 'Invalid session ID format'}), 400
    else:
        session_id = os.urandom(16).hex()
        is_new_session = True

        with session_lock:
            user_sessions = user_session_counts.get(client_fingerprint, 0)
            if user_sessions >= MAX_SESSIONS_PER_USER:
                return jsonify({
                    'error': f'Maximum {MAX_SESSIONS_PER_USER} concurrent sessions allowed per user. Please close existing sessions first.'
                }), 429

            user_session_counts[client_fingerprint] = user_sessions + 1

    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    
    # Validate session exists if not new
    if not is_new_session and not os.path.exists(session_dir):
        return jsonify({'error': 'Session not found'}), 404
    
    # Track session timestamp for cleanup
    _record_session_activity(session_id, fingerprint=client_fingerprint)

    if 'user_sessions' not in session:
        session['user_sessions'] = []
    if session_id not in session['user_sessions']:
        session['user_sessions'].append(session_id)
        session.permanent = True
    
    # Create session directory if new
    if is_new_session:
        if not safe_makedirs(session_dir):
            _clear_session_activity(session_id)
            if 'user_sessions' in session and session_id in session['user_sessions']:
                session['user_sessions'].remove(session_id)
            return jsonify({'error': 'Failed to create upload directory. Permission denied.'}), 500
    
    uploaded_files = []
    existing_paths = set()
    if os.path.exists(session_dir):
        for root, _, files_in_dir in os.walk(session_dir):
            for existing in files_in_dir:
                rel_existing = os.path.relpath(os.path.join(root, existing), session_dir)
                existing_paths.add(os.path.normpath(rel_existing))

    raw_relative_paths = list(request.form.getlist('relative_paths'))
    if len(raw_relative_paths) < len(files):
        raw_relative_paths.extend([''] * (len(files) - len(raw_relative_paths)))

    sanitized_rel_paths = []
    for raw_path in raw_relative_paths:
        rel_dir, rel_filename = _sanitize_relative_path(raw_path)
        sanitized_rel_paths.append((rel_dir, rel_filename))

    try:
        for index, storage_file in enumerate(files):
            if not storage_file:
                continue

            original_filename = storage_file.filename or f"unnamed_file_{index}"

            if original_filename.endswith('/') or original_filename.endswith('\\'):
                # Directory placeholder from folder uploads
                continue

            if not allowed_file(original_filename):
                logger.warning("Rejected file upload (extension policy): %s", original_filename)
                continue

            raw_rel_dir, raw_rel_filename = sanitized_rel_paths[index] if index < len(sanitized_rel_paths) else ('', '')

            sanitized_filename = secure_filename(raw_rel_filename or original_filename)
            if not sanitized_filename:
                sanitized_filename = hashlib.sha1(original_filename.encode('utf-8', errors='ignore') or b'file').hexdigest()[:16]

            if sanitized_filename.startswith('.'):
                sanitized_filename = sanitized_filename.lstrip('.') or sanitized_filename

            if len(sanitized_filename) > 255:
                sanitized_filename = sanitized_filename[:255]

            rel_dir = raw_rel_dir
            target_name = sanitized_filename

            base_name, ext = os.path.splitext(target_name)
            suffix = 1
            rel_candidate = os.path.normpath(os.path.join(rel_dir, target_name)) if rel_dir else os.path.normpath(target_name)

            while rel_candidate in existing_paths or os.path.exists(os.path.join(session_dir, rel_candidate)):
                target_name = f"{base_name}_{suffix}{ext}" if ext else f"{base_name}_{suffix}"
                suffix += 1
                rel_candidate = os.path.normpath(os.path.join(rel_dir, target_name)) if rel_dir else os.path.normpath(target_name)

            target_directory = os.path.join(session_dir, rel_dir) if rel_dir else session_dir
            if rel_dir and not safe_makedirs(target_directory):
                logger.error("Failed to create target directory for upload: %s", target_directory)
                continue

            filepath = os.path.join(target_directory, target_name)
            abs_filepath = os.path.abspath(filepath)
            abs_session_dir = os.path.abspath(session_dir)

            try:
                if os.path.commonpath([abs_filepath, abs_session_dir]) != abs_session_dir:
                    logger.error("Path traversal attempt detected: %s", filepath)
                    continue
            except ValueError:
                logger.error("Invalid path during upload: %s", filepath)
                continue

            storage_file.save(filepath)
            existing_paths.add(rel_candidate)

            is_zip = False
            try:
                with zipfile.ZipFile(filepath, 'r') as test_zip:
                    total_size = sum(info.file_size for info in test_zip.infolist())
                    if total_size > 1024 * 1024 * 1024:
                        logger.warning("ZIP file too large when extracted: %s (%d bytes)", filepath, total_size)
                        os.remove(filepath)
                        existing_paths.discard(rel_candidate)
                        continue

                    for info in test_zip.infolist():
                        if '..' in info.filename or info.filename.startswith('/') or '\\' in info.filename:
                            logger.warning("Malicious path in ZIP file: %s", info.filename)
                            os.remove(filepath)
                            existing_paths.discard(rel_candidate)
                            is_zip = False
                            break
                    else:
                        is_zip = True
            except zipfile.BadZipFile:
                is_zip = False
            except Exception as exc:
                logger.warning("Error processing ZIP file %s: %s", filepath, str(exc))
                is_zip = False

            if is_zip:
                extract_dir = os.path.join(session_dir, f'extracted_{target_name}')
                if not safe_makedirs(extract_dir):
                    os.remove(filepath)
                    existing_paths.discard(rel_candidate)
                    return jsonify({'error': 'Failed to create extraction directory'}), 500

                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)

                os.remove(filepath)
                existing_paths.discard(rel_candidate)

                for root, _, files_in_zip in os.walk(extract_dir):
                    for zip_file in files_in_zip:
                        full_path = os.path.join(root, zip_file)
                        rel_path = os.path.relpath(full_path, session_dir).replace('\\', '/')
                        uploaded_files.append({
                            'name': zip_file,
                            'path': full_path,
                            'relative_path': rel_path,
                            'is_dicom': is_dicom_file(full_path),
                            'from_zip': True,
                            'original_archive': original_filename
                        })
            else:
                normalized_rel_path = rel_candidate.replace('\\', '/')
                uploaded_files.append({
                    'name': target_name,
                    'path': filepath,
                    'relative_path': normalized_rel_path,
                    'is_dicom': is_dicom_file(filepath),
                    'from_zip': False,
                    'original_archive': None
                })
        
        # Clean up non-DICOM files immediately
        deleted_count = cleanup_non_dicom_files(uploaded_files, session_dir)
        
        # Filter out deleted files from the response
        dicom_files = [f for f in uploaded_files if f['is_dicom']]

        new_dicom_paths = [f.get('relative_path') for f in dicom_files if f.get('relative_path')]
        total_session_dicom_count = _register_session_dicom_paths(session_id, new_dicom_paths)

        session_size = _get_directory_size(session_dir)
        _record_session_activity(session_id, session_size, client_fingerprint)

        total_storage = _get_total_storage_usage()
        if total_storage > MAX_TOTAL_STORAGE * 0.8:
            logger.warning(
                "Storage usage at %.1f%% (%d MB / %d MB) after session %s upload",
                (total_storage / MAX_TOTAL_STORAGE) * 100,
                total_storage // (1024 * 1024),
                MAX_TOTAL_STORAGE // (1024 * 1024),
                session_id[:8]
            )
        
        message = f'Added {len(uploaded_files)} files to batch.'
        if deleted_count > 0:
            message += f' {deleted_count} non-DICOM files were automatically removed.'
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'files': dicom_files,
            'new_dicom_count': len(dicom_files),
            'total_dicom_count': total_session_dicom_count,
            'total_count': len(uploaded_files),
            'non_dicom_deleted': deleted_count,
            'message': message,
            'is_new_session': is_new_session
        })
        
    except Exception as exc:
        if is_new_session:
            _clear_session_activity(session_id)
            if 'user_sessions' in session and session_id in session['user_sessions']:
                session['user_sessions'].remove(session_id)
        return jsonify({'error': f'Upload failed: {str(exc)}'}), 500


@app.route('/anonymize', methods=['POST'])
@login_required
def anonymize_files():
    """
    Anonymize uploaded DICOM files using either minimal or standard mode.
    Preserves directory structure and file organization from upload.
    """
    data = request.get_json()
    session_id = data.get('session_id')
    anonymization_mode = data.get('anonymization_mode', 'standard')
    keep_private_tags = data.get('keep_private_tags', False)
    custom_rules = data.get('custom_rules', {})
    
    if not session_id:
        return jsonify({'error': 'No session ID provided'}), 400
    
    input_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    output_session_id = os.urandom(16).hex()
    output_session_dir = os.path.join(app.config['OUTPUT_FOLDER'], output_session_id)
    
    # Track output session timestamp for cleanup
    _record_session_activity(output_session_id)
    
    # Create output directory
    if not safe_makedirs(output_session_dir):
        return jsonify({'error': 'Failed to create output directory. Permission denied.'}), 500
    
    if not os.path.exists(input_dir):
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        # Process anonymization rules based on mode
        extra_anonymization_rules = {}
        
        if anonymization_mode == 'minimal':
            # Use minimal anonymization - only names and IDs
            extra_anonymization_rules = create_minimal_anonymization_rules()
            keep_private_tags = True  # For minimal mode, preserve private tags
        else:
            # Standard mode - process custom rules if provided
            if custom_rules:
                for tag_str, action in custom_rules.items():
                    try:
                        # Convert string tag like "(0x0010, 0x0020)" to tuple
                        tag = eval(tag_str)
                        # Map action name to function
                        from dicomanonymizer.simpledicomanonymizer import (
                            replace, empty, delete, keep as keep_func, replace_UID
                        )
                        action_map = {
                            'replace': replace,
                            'empty': empty,
                            'delete': delete,
                            'keep': keep_func,
                            'replace_UID': replace_UID
                        }
                        if action in action_map:
                            extra_anonymization_rules[tag] = action_map[action]
                    except Exception as e:
                        # Skip invalid rules silently in production
                        continue
        
        # Find all DICOM files and anonymize them while preserving structure
        anonymized_files = []
        file_structure = {}  # Track original structure for reporting
        used_output_rel_paths: Set[str] = set()

        for root, dirs, files in os.walk(input_dir):
            for file in files:
                input_file = os.path.join(root, file)
                if is_dicom_file(input_file):
                    # Preserve the relative path structure in output
                    rel_path = os.path.relpath(input_file, input_dir)
                    dicom_rel_path = _compute_unique_dicom_rel_path(rel_path, used_output_rel_paths)
                    output_file = os.path.join(output_session_dir, dicom_rel_path)
                    
                    # Ensure output directory exists
                    output_dir = os.path.dirname(output_file)
                    if not safe_makedirs(output_dir):
                        return jsonify({'error': f'Failed to create output subdirectory: {output_dir}'}), 500
                    
                    # Track the directory structure
                    dir_key = os.path.dirname(dicom_rel_path) if os.path.dirname(dicom_rel_path) else 'root'
                    if dir_key not in file_structure:
                        file_structure[dir_key] = []
                    file_structure[dir_key].append(os.path.basename(dicom_rel_path))
                    
                    # Anonymize the file
                    if anonymization_mode == 'minimal':
                        # For minimal mode, override base_rules_gen to return empty dict
                        # This prevents default DICOM anonymization and only applies our custom rules
                        anonymize_dicom_file(
                            input_file,
                            output_file,
                            extra_anonymization_rules,
                            delete_private_tags=False,
                            base_rules_gen=lambda: {}  # Return empty dict - no default rules
                        )
                    else:
                        # Standard anonymization
                        anonymize_dicom_file(
                            input_file,
                            output_file,
                            extra_anonymization_rules,
                            delete_private_tags=not keep_private_tags
                        )
                    
                    anonymized_files.append({
                        'original': file,
                        'anonymized': dicom_rel_path,
                        'directory': dir_key
                    })
        
        if not anonymized_files:
            return jsonify({'error': 'No DICOM files found to anonymize'}), 400
        
        return jsonify({
            'success': True,
            'output_session_id': output_session_id,
            'files': anonymized_files,
            'file_structure': file_structure,
            'mode': anonymization_mode,
            'count': len(anonymized_files)
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Anonymization failed: {str(e)}', 
            'traceback': traceback.format_exc()
        }), 500


@app.route('/download/<session_id>')
@login_required
def download_anonymized(session_id):
    """
    Download anonymized files. Single files are served directly,
    multiple files are packaged in a ZIP archive.
    """
    output_dir = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
    
    if not os.path.exists(output_dir):
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        # Collect all files in the output directory
        all_files = []
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
        
        if len(all_files) == 0:
            return jsonify({'error': 'No files found for download'}), 404
        elif len(all_files) == 1:
            # Single file - serve directly without zipping
            single_file = all_files[0]
            download_filename = os.path.basename(single_file)

            return send_file(
                single_file,
                as_attachment=True,
                download_name=download_filename,
                mimetype='application/octet-stream'
            )
        else:
            # Multiple files - create ZIP archive
            zip_path = os.path.join(app.config['OUTPUT_FOLDER'], f'{session_id}_anonymized.zip')
            needs_rebuild = True
            if os.path.exists(zip_path):
                try:
                    zip_mtime = os.path.getmtime(zip_path)
                    latest_source_mtime = max(os.path.getmtime(fp) for fp in all_files)
                    if zip_mtime >= latest_source_mtime:
                        needs_rebuild = False
                except OSError:
                    needs_rebuild = True

            if needs_rebuild:
                compression_kwargs = {}
                if ZIP_COMPRESSLEVEL is not None and ZIP_COMPRESSION == zipfile.ZIP_DEFLATED:
                    compression_kwargs['compresslevel'] = ZIP_COMPRESSLEVEL

                with zipfile.ZipFile(zip_path, 'w', ZIP_COMPRESSION, **compression_kwargs) as zipf:
                    for file_path in all_files:
                        arc_path = os.path.relpath(file_path, output_dir)
                        zipf.write(file_path, arc_path)

            timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')
            download_name = f'{timestamp}-dicom.zip'

            return send_file(
                zip_path,
                as_attachment=True,
                download_name=download_name,
                mimetype='application/zip',
                conditional=True,
                max_age=0
            )
        
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500


@app.route('/cleanup/<session_id>')
@login_required
def cleanup_session(session_id):
    """Manual session cleanup endpoint."""
    try:
        # Clean up upload session
        upload_session = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
        if os.path.exists(upload_session):
            shutil.rmtree(upload_session)
        
        # Clean up output session
        output_session = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
        if os.path.exists(output_session):
            shutil.rmtree(output_session)
        
        # Clean up zip file
        zip_file = os.path.join(app.config['OUTPUT_FOLDER'], f'{session_id}_anonymized.zip')
        if os.path.exists(zip_file):
            os.remove(zip_file)
        
        # Remove from tracking
        _clear_session_activity(session_id)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Cleanup failed: {str(e)}'}), 500


@app.route('/status')
@login_required
def status():
    """Get application status including active sessions."""
    try:
        current_time = time.time()
        active_sessions = []
        
        with session_lock:
            sessions_snapshot = list(session_timestamps.items())

        for session_id, timestamp in sessions_snapshot:
            age_minutes = (current_time - timestamp) / 60
            remaining_minutes = max(SESSION_TIMEOUT_MINUTES_FILE - age_minutes, 0)
            active_sessions.append({
                'session_id': session_id,
                'created': datetime.datetime.fromtimestamp(timestamp).isoformat(),
                'age_minutes': round(age_minutes, 2),
                'expires_in_minutes': round(remaining_minutes, 2)
            })
        
        return jsonify({
            'active_sessions': len(active_sessions),
            'sessions': active_sessions,
            'upload_folder': app.config['UPLOAD_FOLDER'],
            'output_folder': app.config['OUTPUT_FOLDER']
        })
    except Exception as e:
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500


@app.route('/debug-session')
def debug_session():
    """Debug route to check session state (development only)."""
    if IS_PRODUCTION:
        return jsonify({'error': 'Debug endpoint disabled in production'}), 404
    
    return jsonify({
        'session_data': dict(session),
        'authenticated': session.get('authenticated'),
        'login_time': session.get('login_time'),
        'current_time': time.time(),
        'session_permanent': session.permanent,
        'secret_key_set': bool(app.config.get('SECRET_KEY')),
        'secret_key_preview': app.config.get('SECRET_KEY', '')[:10] + '...' if app.config.get('SECRET_KEY') else 'NOT SET',
    'admin_password_set': bool(ADMIN_PASSWORD),
        'request_headers': dict(request.headers),
        'remote_addr': request.remote_addr
    })


@app.route('/debug-login-attempts')
def debug_login_attempts():
    """Debug route to check login attempt state (development only)."""
    if IS_PRODUCTION:
        return jsonify({'error': 'Debug endpoint disabled in production'}), 404
    
    current_time = time.time()
    attempts_debug = {}
    
    for fingerprint, (attempts, first_time) in login_attempts_global.items():
        age_seconds = current_time - first_time
        locked_out, remaining = is_client_locked_out(fingerprint)
        
        attempts_debug[fingerprint[:8] + "..."] = {
            'attempts': attempts,
            'first_attempt_ago_seconds': round(age_seconds, 1),
            'is_locked_out': locked_out,
            'remaining_lockout_seconds': round(remaining, 1) if locked_out else 0,
            'max_attempts': MAX_LOGIN_ATTEMPTS,
            'lockout_duration': LOGIN_LOCKOUT_DURATION
        }
    
    current_fingerprint = get_client_fingerprint(request)
    
    return jsonify({
        'current_fingerprint': current_fingerprint[:8] + "...",
        'max_attempts': MAX_LOGIN_ATTEMPTS,
        'lockout_duration': LOGIN_LOCKOUT_DURATION,
        'active_login_attempts': attempts_debug,
        'total_tracked_clients': len(login_attempts_global),
        'note': 'This debug endpoint helps diagnose brute force protection issues'
    })


@app.errorhandler(413)
def too_large(e):
    """Handle file too large errors."""
    return jsonify({'error': 'File too large. Maximum size is 3GB per session.'}), 413


if __name__ == '__main__':
    logger.info("Starting DICOM Anonymizer Web Application...")
    logger.info("Upload folder: %s", UPLOAD_FOLDER)
    logger.info("Output folder: %s", OUTPUT_FOLDER)
    logger.info("Environment: %s", FLASK_ENV)
    logger.info("Features enabled: content-based validation, zip extraction, cleanup, minimal anonymization, health checks, session auth")

    if IS_PRODUCTION:
        logger.info("Running in PRODUCTION mode")
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        logger.info("Running in DEVELOPMENT mode")
        logger.info("Navigate to http://localhost:5000 to access the application")
        app.run(host='0.0.0.0', port=5000, debug=True)

