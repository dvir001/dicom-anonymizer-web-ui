#!/usr/bin/env python3
"""
Setup script for Docker deployment of DICOM Anonymizer Web Application
"""
import os

def create_requirements():
    """Create requirements.txt file"""
    requirements = """flask>=2.0.0
werkzeug>=2.0.0
pydicom>=2.0.0
tqdm>=4.50.0
"""
    with open('requirements.txt', 'w') as f:
        f.write(requirements)
    print("? Created requirements.txt")

def create_dockerfile():
    """Create Dockerfile"""
    dockerfile_content = """# Use Python 3.9 slim image as base
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Create necessary directories
RUN mkdir -p temp_uploads temp_outputs

# Create a non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \\
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:5000/ || exit 1

# Run the application
CMD ["python", "app.py"]
"""
    with open('Dockerfile', 'w') as f:
        f.write(dockerfile_content)
    print("? Created Dockerfile")

def create_docker_compose():
    """Create docker-compose.yml file"""
    compose_content = """version: '3.8'

services:
  dicom-anonymizer-web:
    build: .
    container_name: dicom-anonymizer-web
    ports:
      - "5000:5000"
    volumes:
      # Optional: Mount directories for persistent storage
      - uploads_data:/app/temp_uploads
      - outputs_data:/app/temp_outputs
    environment:
      - FLASK_ENV=production
      - FLASK_APP=app.py
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - dicom-network

networks:
  dicom-network:
    driver: bridge

volumes:
  uploads_data:
  outputs_data:
"""
    with open('docker-compose.yml', 'w') as f:
        f.write(compose_content)
    print("? Created docker-compose.yml")

def create_dockerignore():
    """Create .dockerignore file"""
    dockerignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Git
.git/
.gitignore

# Docker
Dockerfile*
docker-compose*
.dockerignore

# Local temp directories (these will be created in container)
temp_uploads/
temp_outputs/

# Documentation
*.md
WEB_README.md

# Development files
create_html.py
setup_web_app.py
web_app.py

# Tests
tests/
test_*.py
*_test.py
"""
    with open('.dockerignore', 'w') as f:
        f.write(dockerignore_content)
    print("? Created .dockerignore")

def create_readme():
    """Create Docker README"""
    readme_content = """# DICOM Anonymizer Web Application - Docker Deployment

This directory contains Docker configuration for running the DICOM Anonymizer web application in a containerized environment.

## Quick Start

1. **Build and run with Docker Compose** (recommended):
   ```bash
   docker-compose up --build
   ```

2. **Or build and run with Docker directly**:
   ```bash
   docker build -t dicom-anonymizer-web .
   docker run -p 5000:5000 dicom-anonymizer-web
   ```

3. **Access the application**:
   Open your web browser and navigate to: http://localhost:5000

## Docker Compose Configuration

The `docker-compose.yml` file includes:

- **Port Mapping**: Maps container port 5000 to host port 5000
- **Volume Mounts**: Persistent storage for uploaded and processed files
- **Health Checks**: Monitors application health
- **Restart Policy**: Automatically restarts on failure
- **Custom Network**: Isolated network for the application

## Features

- **Secure**: Runs as non-root user inside container
- **Persistent Storage**: Files persist between container restarts
- **Health Monitoring**: Built-in health checks
- **Production Ready**: Optimized for production deployment

## File Structure

```
.
??? Dockerfile              # Container definition
??? docker-compose.yml      # Multi-container orchestration
??? requirements.txt        # Python dependencies
??? .dockerignore          # Files to exclude from build
??? app.py                 # Flask web application
??? templates/
?   ??? index.html         # Web interface
??? dicomanonymizer/       # Core anonymization library
```

## Configuration

### Environment Variables

- `FLASK_ENV`: Set to 'production' for production deployment
- `FLASK_APP`: Points to the main application file (app.py)

### Ports

- **5000**: Web application port (HTTP)

### Volumes

- `uploads_data`: Persistent storage for uploaded files
- `outputs_data`: Persistent storage for anonymized files

## Usage

1. **Start the service**:
   ```bash
   docker-compose up -d
   ```

2. **View logs**:
   ```bash
   docker-compose logs -f
   ```

3. **Stop the service**:
   ```bash
   docker-compose down
   ```

4. **Rebuild after changes**:
   ```bash
   docker-compose up --build
   ```

## Security Considerations

- Application runs as non-root user
- Only necessary ports are exposed
- File uploads are validated and sanitized
- Temporary files are automatically cleaned up

## Troubleshooting

### Common Issues

1. **Port already in use**:
   - Change the port mapping in docker-compose.yml: `"8080:5000"`

2. **Permission issues**:
   - Ensure Docker has proper permissions
   - Check volume mount permissions

3. **Build failures**:
   - Ensure all required files are present
   - Check internet connectivity for package downloads

### Logs and Debugging

```bash
# View application logs
docker-compose logs dicom-anonymizer-web

# Execute commands inside container
docker-compose exec dicom-anonymizer-web bash

# Check container health
docker-compose ps
```

## Development

For development with live reloading:

```bash
# Mount source code as volume
docker-compose -f docker-compose.dev.yml up
```

## Production Deployment

For production deployment:

1. **Use a reverse proxy** (nginx, traefik)
2. **Enable HTTPS/SSL**
3. **Configure proper logging**
4. **Set up monitoring**
5. **Regular backups of persistent volumes**

## Scaling

To run multiple instances:

```bash
docker-compose up --scale dicom-anonymizer-web=3
```

Note: You'll need a load balancer for multiple instances.
"""
    with open('DOCKER_README.md', 'w') as f:
        f.write(readme_content)
    print("? Created DOCKER_README.md")

def main():
    """Main setup function"""
    print("?? Setting up Docker configuration for DICOM Anonymizer Web App")
    print("=" * 65)
    
    create_requirements()
    create_dockerfile()
    create_docker_compose()
    create_dockerignore()
    create_readme()
    
    print("\n?? Docker setup complete!")
    print("\nNext steps:")
    print("1. Build and run: docker-compose up --build")
    print("2. Access: http://localhost:5000")
    print("3. Upload DICOM files and anonymize!")
    print("\nFor production deployment, see DOCKER_README.md")

if __name__ == "__main__":
    main()