import os

# Prevent Flask app from failing on missing env vars during tests
os.environ.setdefault('FLASK_ENV', 'testing')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-only')
os.environ.setdefault('AZURE_CLIENT_ID', '')
os.environ.setdefault('AZURE_TENANT_ID', '')
