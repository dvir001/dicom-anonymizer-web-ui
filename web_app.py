# Flask DICOM Anonymizer Web Application
import os
import tempfile
import shutil
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import zipfile
from dicomanonymizer import anonymize
from dicomanonymizer.simpledicomanonymizer import anonymize_dicom_file
from dicomanonymizer.anonymizer import isDICOMType
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dicom-anonymizer-secret-key-2024'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
app.config['OUTPUT_FOLDER'] = tempfile.mkdtemp()

# Ensure upload and output folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'dcm', 'dicom', 'ima', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_dicom_file(filepath):
    """Check if file is a DICOM file using the existing function"""
    return isDICOMType(filepath)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400
    
    uploaded_files = []
    session_id = tempfile.mkdtemp(dir=app.config['UPLOAD_FOLDER'])
    
    try:
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(session_id, filename)
                file.save(filepath)
                
                # Handle ZIP files
                if filename.lower().endswith('.zip'):
                    extract_dir = os.path.join(session_id, 'extracted')
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    with zipfile.ZipFile(filepath, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    
                    # Find DICOM files in extracted content
                    for root, dirs, files_in_zip in os.walk(extract_dir):
                        for zip_file in files_in_zip:
                            full_path = os.path.join(root, zip_file)
                            if is_dicom_file(full_path):
                                uploaded_files.append({
                                    'name': zip_file,
                                    'path': full_path,
                                    'is_dicom': True
                                })
                else:
                    # Check if it's a DICOM file
                    is_dicom = is_dicom_file(filepath)
                    uploaded_files.append({
                        'name': filename,
                        'path': filepath,
                        'is_dicom': is_dicom
                    })
        
        return jsonify({
            'success': True,
            'session_id': os.path.basename(session_id),
            'files': uploaded_files,
            'dicom_count': len([f for f in uploaded_files if f['is_dicom']])
        })
        
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/anonymize', methods=['POST'])
def anonymize_files():
    data = request.get_json()
    session_id = data.get('session_id')
    keep_private_tags = data.get('keep_private_tags', False)
    custom_rules = data.get('custom_rules', {})
    
    if not session_id:
        return jsonify({'error': 'No session ID provided'}), 400
    
    input_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    output_session_dir = tempfile.mkdtemp(dir=app.config['OUTPUT_FOLDER'])
    
    if not os.path.exists(input_dir):
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        # Process custom rules if provided
        extra_anonymization_rules = {}
        if custom_rules:
            for tag_str, action in custom_rules.items():
                try:
                    # Convert string tag like "(0x0010, 0x0020)" to tuple
                    tag = eval(tag_str)
                    # Map action name to function (simplified for web interface)
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
                except:
                    continue  # Skip invalid rules
        
        # Find all DICOM files and anonymize them
        anonymized_files = []
        
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                input_file = os.path.join(root, file)
                if is_dicom_file(input_file):
                    # Create relative path structure in output
                    rel_path = os.path.relpath(input_file, input_dir)
                    output_file = os.path.join(output_session_dir, rel_path)
                    
                    # Ensure output directory exists
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    
                    # Anonymize the file
                    anonymize_dicom_file(
                        input_file,
                        output_file,
                        extra_anonymization_rules,
                        delete_private_tags=not keep_private_tags
                    )
                    
                    anonymized_files.append({
                        'original': file,
                        'anonymized': rel_path
                    })
        
        if not anonymized_files:
            return jsonify({'error': 'No DICOM files found to anonymize'}), 400
        
        return jsonify({
            'success': True,
            'output_session_id': os.path.basename(output_session_dir),
            'files': anonymized_files,
            'count': len(anonymized_files)
        })
        
    except Exception as e:
        return jsonify({'error': f'Anonymization failed: {str(e)}'}), 500

@app.route('/download/<session_id>')
def download_anonymized(session_id):
    output_dir = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
    
    if not os.path.exists(output_dir):
        return jsonify({'error': 'Session not found'}), 404
    
    try:
        # Create a ZIP file with all anonymized files
        zip_path = os.path.join(app.config['OUTPUT_FOLDER'], f'{session_id}_anonymized.zip')
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arc_path = os.path.relpath(file_path, output_dir)
                    zipf.write(file_path, arc_path)
        
        return send_file(
            zip_path,
            as_attachment=True,
            download_name='anonymized_dicom_files.zip',
            mimetype='application/zip'
        )
        
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/cleanup/<session_id>')
def cleanup_session(session_id):
    """Clean up session files"""
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
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Cleanup failed: {str(e)}'}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 500MB.'}), 413

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)