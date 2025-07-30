#!/usr/bin/env python3
"""
DICOM Anonymizer Web Application Setup Script
This script sets up and runs the web-based DICOM anonymizer.
"""

import os
import sys

def create_html_template():
    """Create the HTML template file if it doesn't exist"""
    template_dir = "templates"
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
    
    html_file = os.path.join(template_dir, "index.html")
    if not os.path.exists(html_file) or os.path.getsize(html_file) == 0:
        html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>DICOM Anonymizer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        .upload-area { border: 2px dashed #ccc; padding: 40px; text-align: center; margin: 20px 0; cursor: pointer; }
        .upload-area:hover { border-color: #007bff; background: #f8f9ff; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .btn:disabled { background: #ccc; cursor: not-allowed; }
        .hidden { display: none; }
        .file-item { padding: 10px; background: #f8f9fa; margin: 5px 0; border-radius: 5px; }
        .status { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        .status.info { background: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="container">
        <h1>?? DICOM Anonymizer</h1>
        <p>Secure web-based DICOM file anonymization</p>
        
        <div class="upload-area" id="uploadArea">
            <h3>?? Upload DICOM Files</h3>
            <p>Click to select files or drag and drop</p>
            <p><small>Supports .dcm, .dicom, .ima files and .zip archives (Max: 500MB)</small></p>
            <input type="file" id="fileInput" multiple accept=".dcm,.dicom,.ima,.zip" style="display: none;">
        </div>

        <div id="fileList" class="hidden"></div>
        <div id="uploadStatus" class="hidden"></div>

        <div id="optionsCard" class="hidden">
            <h3>?? Options</h3>
            <label>
                <input type="checkbox" id="keepPrivateTags"> Keep private DICOM tags
            </label>
            <p><small>By default, private tags are removed for maximum anonymization</small></p>
            <br>
            <button id="anonymizeBtn" class="btn" onclick="startAnonymization()">?? Start Anonymization</button>
        </div>

        <div id="resultsCard" class="hidden">
            <h3>? Anonymization Complete</h3>
            <div id="resultsStatus"></div>
            <button id="downloadBtn" class="btn">?? Download Files</button>
            <button class="btn" onclick="startOver()">?? Start Over</button>
        </div>
    </div>

    <script>
        let currentSession = null;
        let currentOutputSession = null;

        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const fileList = document.getElementById('fileList');
        const uploadStatus = document.getElementById('uploadStatus');
        const optionsCard = document.getElementById('optionsCard');
        const resultsCard = document.getElementById('resultsCard');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.style.borderColor = '#007bff'; });
        uploadArea.addEventListener('dragleave', (e) => { e.preventDefault(); uploadArea.style.borderColor = '#ccc'; });
        uploadArea.addEventListener('drop', (e) => { 
            e.preventDefault(); 
            uploadArea.style.borderColor = '#ccc';
            const files = Array.from(e.dataTransfer.files);
            uploadFiles(files);
        });
        fileInput.addEventListener('change', (e) => uploadFiles(Array.from(e.target.files)));

        async function uploadFiles(files) {
            if (files.length === 0) return;

            const formData = new FormData();
            files.forEach(file => formData.append('files', file));

            showStatus('Uploading files...', 'info');

            try {
                const response = await fetch('/upload', { method: 'POST', body: formData });
                const result = await response.json();

                if (result.success) {
                    currentSession = result.session_id;
                    displayUploadedFiles(result.files);
                    showStatus(`Successfully uploaded ${result.files.length} files (${result.dicom_count} DICOM files)`, 'success');
                    optionsCard.classList.remove('hidden');
                } else {
                    showStatus(`Upload failed: ${result.error}`, 'error');
                }
            } catch (error) {
                showStatus(`Upload failed: ${error.message}`, 'error');
            }
        }

        function displayUploadedFiles(files) {
            fileList.innerHTML = '<h4>?? Uploaded Files:</h4>';
            files.forEach(file => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                fileItem.innerHTML = `${file.name} - ${file.is_dicom ? '? DICOM' : '? Not DICOM'}`;
                fileList.appendChild(fileItem);
            });
            fileList.classList.remove('hidden');
        }

        async function startAnonymization() {
            if (!currentSession) {
                showStatus('No files uploaded', 'error');
                return;
            }

            const anonymizeBtn = document.getElementById('anonymizeBtn');
            anonymizeBtn.disabled = true;
            anonymizeBtn.textContent = '? Anonymizing...';

            const keepPrivateTags = document.getElementById('keepPrivateTags').checked;
            showStatus('Anonymizing DICOM files...', 'info');

            try {
                const response = await fetch('/anonymize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        session_id: currentSession,
                        keep_private_tags: keepPrivateTags,
                        custom_rules: {}
                    })
                });

                const result = await response.json();

                if (result.success) {
                    currentOutputSession = result.output_session_id;
                    showAnonymizationResults(result);
                } else {
                    showStatus(`Anonymization failed: ${result.error}`, 'error');
                    anonymizeBtn.disabled = false;
                    anonymizeBtn.textContent = '?? Start Anonymization';
                }
            } catch (error) {
                showStatus(`Anonymization failed: ${error.message}`, 'error');
                anonymizeBtn.disabled = false;
                anonymizeBtn.textContent = '?? Start Anonymization';
            }
        }

        function showAnonymizationResults(result) {
            const resultsStatus = document.getElementById('resultsStatus');
            resultsStatus.innerHTML = `
                <div class="status success">
                    ? Successfully anonymized ${result.count} DICOM files
                </div>
            `;

            const downloadBtn = document.getElementById('downloadBtn');
            downloadBtn.onclick = () => downloadAnonymizedFiles();

            optionsCard.classList.add('hidden');
            resultsCard.classList.remove('hidden');
        }

        function downloadAnonymizedFiles() {
            if (currentOutputSession) {
                window.location.href = `/download/${currentOutputSession}`;
                setTimeout(() => {
                    fetch(`/cleanup/${currentOutputSession}`);
                    fetch(`/cleanup/${currentSession}`);
                }, 2000);
            }
        }

        function startOver() {
            if (currentOutputSession) fetch(`/cleanup/${currentOutputSession}`);
            if (currentSession) fetch(`/cleanup/${currentSession}`);

            currentSession = null;
            currentOutputSession = null;
            fileInput.value = '';
            fileList.classList.add('hidden');
            optionsCard.classList.add('hidden');
            resultsCard.classList.add('hidden');
            uploadStatus.classList.add('hidden');
        }

        function showStatus(message, type) {
            uploadStatus.className = `status ${type}`;
            uploadStatus.textContent = message;
            uploadStatus.classList.remove('hidden');
        }
    </script>
</body>
</html>'''
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"? Created {html_file}")

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import flask
        print("? Flask is installed")
    except ImportError:
        print("? Flask is not installed. Run: pip install flask")
        return False
    
    try:
        import dicomanonymizer
        print("? DICOM Anonymizer is installed")
    except ImportError:
        print("? DICOM Anonymizer is not installed. Run: pip install dicom-anonymizer")
        return False
    
    return True

def main():
    """Main setup function"""
    print("?? DICOM Anonymizer Web Application Setup")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("\n? Please install missing dependencies and try again.")
        return False
    
    # Create HTML template
    create_html_template()
    
    # Create directories
    for directory in ['temp_uploads', 'temp_outputs']:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"? Created {directory} directory")
    
    print("\n?? Setup complete!")
    print("\nTo start the web application:")
    print("1. Run: python app.py")
    print("2. Open your browser to: http://localhost:5000")
    print("\nFeatures:")
    print("- Upload DICOM files or ZIP archives")
    print("- Drag & drop file upload")
    print("- Choose privacy settings")
    print("- Download anonymized files")
    print("- Automatic cleanup")
    
    return True

if __name__ == "__main__":
    main()