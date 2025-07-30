with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DICOM Anonymizer - Web Interface</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
            color: white;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        .upload-area {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            background: #f8f9ff;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .upload-area:hover {
            border-color: #764ba2;
            background: #f0f2ff;
        }

        .upload-area.drag-over {
            border-color: #28a745;
            background: #f0fff0;
        }

        .upload-icon {
            font-size: 4rem;
            color: #667eea;
            margin-bottom: 20px;
        }

        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            margin: 10px 5px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        }

        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%);
        }

        .btn-secondary {
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
        }

        .file-list {
            margin: 20px 0;
            max-height: 300px;
            overflow-y: auto;
        }

        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 5px;
            border-left: 4px solid #667eea;
        }

        .file-item.dicom {
            border-left-color: #28a745;
        }

        .file-item.non-dicom {
            border-left-color: #ffc107;
        }

        .status {
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-weight: 600;
        }

        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .status.info {
            background: #cce7ff;
            color: #004085;
            border: 1px solid #b3d7ff;
        }

        .hidden {
            display: none;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .small {
            font-size: 0.9rem;
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>?? DICOM Anonymizer</h1>
            <p>Secure web-based DICOM file anonymization</p>
        </div>

        <div class="card">
            <h2>?? Upload DICOM Files</h2>
            <div class="upload-area" id="uploadArea">
                <div class="upload-icon">??</div>
                <h3>Drop DICOM files here or click to browse</h3>
                <p>Supports .dcm, .dicom, .ima files and .zip archives</p>
                <p class="small">Maximum file size: 500MB</p>
                <input type="file" id="fileInput" multiple accept=".dcm,.dicom,.ima,.zip" style="display: none;">
            </div>

            <div id="fileList" class="file-list hidden"></div>
            <div id="uploadStatus" class="hidden"></div>
        </div>

        <div class="card hidden" id="optionsCard">
            <h2>?? Anonymization Options</h2>
            
            <div style="margin: 20px 0;">
                <label>
                    <input type="checkbox" id="keepPrivateTags" style="margin-right: 10px;">
                    Keep private DICOM tags
                </label>
                <p class="small">By default, private tags are removed for maximum anonymization</p>
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <button id="anonymizeBtn" class="btn btn-success" onclick="startAnonymization()">
                    ?? Start Anonymization
                </button>
            </div>
        </div>

        <div class="card hidden" id="resultsCard">
            <h2>? Anonymization Complete</h2>
            <div id="resultsStatus"></div>
            <div style="text-align: center; margin-top: 20px;">
                <button id="downloadBtn" class="btn btn-success">
                    ?? Download Anonymized Files
                </button>
                <button class="btn btn-secondary" onclick="startOver()">
                    ?? Start Over
                </button>
            </div>
        </div>
    </div>

    <script>
        let currentSession = null;
        let currentOutputSession = null;

        // File upload handling
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const fileList = document.getElementById('fileList');
        const uploadStatus = document.getElementById('uploadStatus');
        const optionsCard = document.getElementById('optionsCard');
        const resultsCard = document.getElementById('resultsCard');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', handleDragOver);
        uploadArea.addEventListener('dragleave', handleDragLeave);
        uploadArea.addEventListener('drop', handleDrop);
        fileInput.addEventListener('change', handleFileSelect);

        function handleDragOver(e) {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        }

        function handleDragLeave(e) {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
        }

        function handleDrop(e) {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const files = Array.from(e.dataTransfer.files);
            uploadFiles(files);
        }

        function handleFileSelect(e) {
            const files = Array.from(e.target.files);
            uploadFiles(files);
        }

        async function uploadFiles(files) {
            if (files.length === 0) return;

            const formData = new FormData();
            files.forEach(file => formData.append('files', file));

            showStatus('Uploading files...', 'info');

            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });

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
            fileList.innerHTML = '';
            files.forEach(file => {
                const fileItem = document.createElement('div');
                fileItem.className = `file-item ${file.is_dicom ? 'dicom' : 'non-dicom'}`;
                fileItem.innerHTML = `
                    <span>${file.name}</span>
                    <span class="badge">${file.is_dicom ? '? DICOM' : '? Not DICOM'}</span>
                `;
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
            anonymizeBtn.innerHTML = '<span class="loading"></span>Anonymizing...';

            const keepPrivateTags = document.getElementById('keepPrivateTags').checked;

            showStatus('Anonymizing DICOM files...', 'info');

            try {
                const response = await fetch('/anonymize', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
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
                    anonymizeBtn.innerHTML = '?? Start Anonymization';
                }
            } catch (error) {
                showStatus(`Anonymization failed: ${error.message}`, 'error');
                anonymizeBtn.disabled = false;
                anonymizeBtn.innerHTML = '?? Start Anonymization';
            }
        }

        function showAnonymizationResults(result) {
            const resultsStatus = document.getElementById('resultsStatus');
            resultsStatus.innerHTML = `
                <div class="status success">
                    ? Successfully anonymized ${result.count} DICOM files
                </div>
                <div class="file-list">
                    ${result.files.map(file => `
                        <div class="file-item dicom">
                            <span>${file.original}</span>
                            <span>?? Anonymized</span>
                        </div>
                    `).join('')}
                </div>
            `;

            // Setup download button
            const downloadBtn = document.getElementById('downloadBtn');
            downloadBtn.onclick = () => downloadAnonymizedFiles();

            optionsCard.classList.add('hidden');
            resultsCard.classList.remove('hidden');
        }

        function downloadAnonymizedFiles() {
            if (currentOutputSession) {
                window.location.href = `/download/${currentOutputSession}`;
                // Cleanup after download
                setTimeout(() => {
                    fetch(`/cleanup/${currentOutputSession}`);
                    fetch(`/cleanup/${currentSession}`);
                }, 2000);
            }
        }

        function startOver() {
            // Cleanup sessions
            if (currentOutputSession) {
                fetch(`/cleanup/${currentOutputSession}`);
            }
            if (currentSession) {
                fetch(`/cleanup/${currentSession}`);
            }

            // Reset UI
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
</html>''')
print("Created templates/index.html successfully!")