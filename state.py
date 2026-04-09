"""
Redis-backed shared state for multi-worker deployments.

Replaces the in-memory dicts (session_timestamps, session_metadata,
user_session_counts, _assembly_progress, name_mapping_cache, storage cache)
so that multiple Gunicorn workers share a single source of truth.

All keys are prefixed with 'dicom:' to namespace within the Redis instance.
"""

from __future__ import annotations

import json
import time
import hashlib
import logging
import os

import redis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

_pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)


def get_redis() -> redis.Redis:
    """Return a Redis client from the shared connection pool."""
    return redis.Redis(connection_pool=_pool)


def check_redis_health() -> bool:
    """Return True if Redis is reachable."""
    try:
        return get_redis().ping()
    except redis.RedisError:
        return False


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

_PREFIX = 'dicom:'

# Hash keys
_SESSION_TS = f'{_PREFIX}session_ts'            # hash: session_id -> timestamp (float)
_SESSION_META = f'{_PREFIX}session_meta'        # hash: session_id -> JSON metadata
_USER_SESSIONS = f'{_PREFIX}user_sessions'      # hash: fingerprint -> count (int)
_NAME_CACHE = f'{_PREFIX}name_cache'            # hash: name -> random_number
_STORAGE_CACHE = f'{_PREFIX}storage_cache'      # string key for cached storage total


def _progress_key(upload_id: str) -> str:
    return f'{_PREFIX}progress:{upload_id}'


# ---------------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------------

def record_session_activity(session_id: str, session_size: int = 0,
                            fingerprint: str | None = None) -> None:
    """Record that a session is active. Creates metadata if new."""
    r = get_redis()
    now = time.time()

    r.hset(_SESSION_TS, session_id, str(now))

    raw = r.hget(_SESSION_META, session_id)
    if raw:
        meta = json.loads(raw)
    else:
        meta = {
            'created': now,
            'last_size': 0,
            'fingerprint': fingerprint,
            'dicom_paths': [],
            'dicom_count': 0,
        }

    meta.setdefault('created', now)
    if fingerprint:
        meta['fingerprint'] = fingerprint
    if session_size >= 0:
        meta['last_size'] = session_size

    r.hset(_SESSION_META, session_id, json.dumps(meta))


def clear_session_activity(session_id: str) -> None:
    """Remove a session from tracking and decrement user session count."""
    r = get_redis()
    r.hdel(_SESSION_TS, session_id)

    raw = r.hget(_SESSION_META, session_id)
    if raw:
        meta = json.loads(raw)
        fingerprint = meta.get('fingerprint')
        if fingerprint:
            new_val = r.hincrby(_USER_SESSIONS, fingerprint, -1)
            if new_val <= 0:
                r.hdel(_USER_SESSIONS, fingerprint)
    r.hdel(_SESSION_META, session_id)


def active_session_count() -> int:
    """Return the number of tracked sessions."""
    return get_redis().hlen(_SESSION_TS)


def get_sessions_snapshot() -> list[tuple[str, float]]:
    """Return a list of (session_id, timestamp) tuples."""
    r = get_redis()
    data = r.hgetall(_SESSION_TS)
    return [(sid, float(ts)) for sid, ts in data.items()]


def increment_user_sessions(fingerprint: str) -> int:
    """Atomically increment and return the new count for a user."""
    return get_redis().hincrby(_USER_SESSIONS, fingerprint, 1)


def get_user_session_count(fingerprint: str) -> int:
    """Return the current session count for a user."""
    val = get_redis().hget(_USER_SESSIONS, fingerprint)
    return int(val) if val else 0


# ---------------------------------------------------------------------------
# DICOM path tracking (stored inside session metadata)
# ---------------------------------------------------------------------------

def register_session_dicom_paths(session_id: str,
                                 new_paths: list[str] | None = None) -> int:
    """Add DICOM paths to a session and return the updated count."""
    r = get_redis()
    raw = r.hget(_SESSION_META, session_id)
    meta = json.loads(raw) if raw else {
        'created': time.time(), 'last_size': 0,
        'fingerprint': None, 'dicom_paths': [], 'dicom_count': 0,
    }

    tracked = set(meta.get('dicom_paths') or [])
    if new_paths:
        tracked.update(p for p in new_paths if p)

    meta['dicom_paths'] = list(tracked)
    meta['dicom_count'] = len(tracked)
    r.hset(_SESSION_META, session_id, json.dumps(meta))
    return meta['dicom_count']


def get_tracked_dicom_paths(session_id: str) -> set[str]:
    """Return a set of tracked DICOM paths for a session."""
    r = get_redis()
    raw = r.hget(_SESSION_META, session_id)
    if not raw:
        return set()
    meta = json.loads(raw)
    return set(meta.get('dicom_paths') or [])


def get_session_metadata(session_id: str) -> dict | None:
    """Return metadata dict for a session, or None."""
    r = get_redis()
    raw = r.hget(_SESSION_META, session_id)
    return json.loads(raw) if raw else None


# ---------------------------------------------------------------------------
# Assembly progress tracking
# ---------------------------------------------------------------------------

_PROGRESS_TTL = 600  # 10 minutes

def set_assembly_progress(upload_id: str, stage: str,
                          detail: str = '', percent: int = 0) -> None:
    """Update the progress state for a chunked upload assembly."""
    r = get_redis()
    data = json.dumps({
        'stage': stage,
        'detail': detail,
        'percent': percent,
        'updated': time.time(),
    })
    r.setex(_progress_key(upload_id), _PROGRESS_TTL, data)


def get_assembly_progress(upload_id: str) -> dict | None:
    """Get the current progress state for a chunked upload assembly."""
    r = get_redis()
    raw = r.get(_progress_key(upload_id))
    if not raw:
        return None
    return json.loads(raw)


def clear_assembly_progress(upload_id: str) -> None:
    """Remove progress tracking for a completed assembly."""
    get_redis().delete(_progress_key(upload_id))


# ---------------------------------------------------------------------------
# Name mapping cache (consistent anonymization)
# ---------------------------------------------------------------------------

MAX_NAME_CACHE_SIZE = 10000


def get_consistent_random_number(name: str) -> str:
    """Generate a consistent random number for a given name using SHA-256."""
    r = get_redis()

    cached = r.hget(_NAME_CACHE, name)
    if cached is not None:
        return cached

    hash_hex = hashlib.sha256(name.encode('utf-8')).hexdigest()
    random_number = str(int(hash_hex[:8], 16))[-6:]

    # Bounded cache — if too large, flush it (rare; hash is deterministic so
    # losing the cache is harmless)
    if r.hlen(_NAME_CACHE) >= MAX_NAME_CACHE_SIZE:
        r.delete(_NAME_CACHE)

    r.hset(_NAME_CACHE, name, random_number)
    return random_number


# ---------------------------------------------------------------------------
# Storage usage cache
# ---------------------------------------------------------------------------

_STORAGE_KEY = f'{_PREFIX}storage_total'
_STORAGE_TS_KEY = f'{_PREFIX}storage_ts'
STORAGE_CACHE_TTL = 30  # seconds


def get_cached_storage_total() -> tuple[float | None, int | None]:
    """Return (timestamp, total) if cached, else (None, None)."""
    r = get_redis()
    pipe = r.pipeline()
    pipe.get(_STORAGE_TS_KEY)
    pipe.get(_STORAGE_KEY)
    ts_raw, total_raw = pipe.execute()
    if ts_raw and total_raw:
        return float(ts_raw), int(total_raw)
    return None, None


def set_cached_storage_total(total: int) -> None:
    """Cache the current storage total with a timestamp."""
    r = get_redis()
    pipe = r.pipeline()
    pipe.setex(_STORAGE_TS_KEY, STORAGE_CACHE_TTL + 5, str(time.time()))
    pipe.setex(_STORAGE_KEY, STORAGE_CACHE_TTL + 5, str(total))
    pipe.execute()
