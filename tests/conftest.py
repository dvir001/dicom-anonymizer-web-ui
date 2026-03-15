import os
import tempfile
import shutil
import pytest

# Prevent Flask app from failing on missing env vars during tests
os.environ.setdefault('FLASK_ENV', 'testing')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-only')
os.environ.setdefault('AZURE_CLIENT_ID', '')
os.environ.setdefault('AZURE_TENANT_ID', '')

# Ensure the app's root directory is isolated during tests so that
# importing the Flask app does not create directories under the repo root
_TEST_DICOM_APP_ROOT = os.environ.setdefault(
    'DICOM_APP_ROOT',
    tempfile.mkdtemp(prefix='dicom_app_test_')
)

@pytest.fixture(scope="session", autouse=True)
def _cleanup_dicom_app_root():
    """
    Remove the temporary DICOM_APP_ROOT directory after the test session.
    """
    yield
    shutil.rmtree(_TEST_DICOM_APP_ROOT, ignore_errors=True)
