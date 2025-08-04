# Flask DICOM Anonymizer Web Application
import os
import tempfile
import shutil
import threading
import time
import datetime
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
import zipfile
from dicomanonymizer.simpledicomanonymizer import anonymize_dicom_file
from dicomanonymizer.anonymizer import isDICOMType
import json
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dicom-anonymizer-secret-key-2024'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size

# Create temp directories for uploads and outputs
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'temp_uploads')
OUTPUT_FOLDER = os.path.join(os.getcwd(), 'temp_outputs')

try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    print(f"✓ Created directories: {UPLOAD_FOLDER}, {OUTPUT_FOLDER}")
except PermissionError as e:
    print(f"⚠ Permission error creating directories: {e}")
    # Fallback to system temp directory
    UPLOAD_FOLDER = tempfile.mkdtemp(prefix='dicom_uploads_')
    OUTPUT_FOLDER = tempfile.mkdtemp(prefix='dicom_outputs_')
    print(f"⚠⚠ Using fallback directories: {UPLOAD_FOLDER}, {OUTPUT_FOLDER}")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

# File tracking for automatic cleanup
session_timestamps = {}

def allowed_file(filename):
    """
    Allow all files regardless of extension.
    We'll check if they're DICOM files using the content-based check.
    """
    # Allow all files - we'll check DICOM validity by content
    return True

def is_dicom_file(filepath):
    """Check if file is a DICOM file using the existing function"""
    try:
        return isDICOMType(filepath)
    except:
        return False

def safe_makedirs(path):
    """Safely create directories with error handling"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except PermissionError as e:
        print(f"⚠ Permission error creating directory {path}: {e}")
        return False
    except Exception as e:
        print(f"⚠ Error creating directory {path}: {e}")
        return False

def cleanup_non_dicom_files(uploaded_files, session_dir):
    """
    Immediately delete non-DICOM files to save space and improve security
    """
    files_deleted = 0
    for file_info in uploaded_files:
        if not file_info['is_dicom']:
            try:
                file_path = file_info['path']
                if os.path.exists(file_path):
                    os.remove(file_path)
                    files_deleted += 1
                    print(f"🗑️ Immediately deleted non-DICOM file: {file_info['name']}")
            except Exception as e:
                print(f"⚠ Error deleting non-DICOM file {file_info['name']}: {e}")
    
    # Also clean up empty directories from ZIP extraction
    try:
        extract_dir = os.path.join(session_dir, 'extracted')
        if os.path.exists(extract_dir):
            # Check if extract_dir is empty or only contains non-DICOM files
            remaining_dicom_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    if is_dicom_file(full_path):
                        remaining_dicom_files.append(full_path)
            
            # If no DICOM files remain in extracted directory, remove it
            if not remaining_dicom_files:
                shutil.rmtree(extract_dir)
                print(f"🗑️ Removed empty extraction directory: {extract_dir}")
    except Exception as e:
        print(f"⚠ Error cleaning up extraction directory: {e}")
    
    return files_deleted

def cleanup_old_sessions():
    """
    Background task to clean up sessions older than 10 minutes
    """
    while True:
        try:
            current_time = time.time()
            sessions_to_remove = []
            
            for session_id, timestamp in session_timestamps.items():
                # Check if session is older than 10 minutes (600 seconds)
                if current_time - timestamp > 600:
                    sessions_to_remove.append(session_id)
            
            # Clean up old sessions
            for session_id in sessions_to_remove:
                try:
                    # Clean up upload session
                    upload_session = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
                    if os.path.exists(upload_session):
                        shutil.rmtree(upload_session)
                        print(f"🧹 Cleaned up old upload session: {session_id}")
                    
                    # Clean up output session
                    output_session = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
                    if os.path.exists(output_session):
                        shutil.rmtree(output_session)
                        print(f"🧹 Cleaned up old output session: {session_id}")
                    
                    # Clean up zip files
                    zip_file = os.path.join(app.config['OUTPUT_FOLDER'], f'{session_id}_anonymized.zip')
                    if os.path.exists(zip_file):
                        os.remove(zip_file)
                        print(f"🧹 Cleaned up old zip file: {session_id}")
                    
                    # Remove from tracking
                    del session_timestamps[session_id]
                    
                except Exception as e:
                    print(f"⚠ Error cleaning up session {session_id}: {e}")
            
            # Sleep for 1 minute before next cleanup check
            time.sleep(60)
            
        except Exception as e:
            print(f"⚠ Error in cleanup thread: {e}")
            time.sleep(60)  # Continue checking even if there's an error

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
cleanup_thread.start()

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
    session_id = os.urandom(16).hex()
    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    
    # Track session timestamp for cleanup
    session_timestamps[session_id] = time.time()
    
    # Use safe directory creation
    if not safe_makedirs(session_dir):
        return jsonify({'error': 'Failed to create upload directory. Permission denied.'}), 500
    
    try:
        for file in files:
            if file:  # Accept all files regardless of extension
                filename = secure_filename(file.filename) if file.filename else f"unnamed_file_{len(uploaded_files)}"
                filepath = os.path.join(session_dir, filename)
                file.save(filepath)
                
                # Handle ZIP files (check by content, not just extension)
                is_zip = False
                try:
                    with zipfile.ZipFile(filepath, 'r') as test_zip:
                        is_zip = True
                except:
                    is_zip = False
                
                if is_zip:
                    extract_dir = os.path.join(session_dir, 'extracted')
                    if not safe_makedirs(extract_dir):
                        return jsonify({'error': 'Failed to create extraction directory'}), 500
                    
                    with zipfile.ZipFile(filepath, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    
                    # Remove the original ZIP file after extraction
                    os.remove(filepath)
                    print(f"🗑️ Removed original ZIP file: {filename}")
                    
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
                                # Add non-DICOM files to list for immediate deletion
                                uploaded_files.append({
                                    'name': zip_file,
                                    'path': full_path,
                                    'is_dicom': False
                                })
                else:
                    # Check if it's a DICOM file (works for files with or without extensions)
                    is_dicom = is_dicom_file(filepath)
                    uploaded_files.append({
                        'name': filename,
                        'path': filepath,
                        'is_dicom': is_dicom
                    })
        
        # Immediately clean up non-DICOM files
        deleted_count = cleanup_non_dicom_files(uploaded_files, session_dir)
        
        # Filter out deleted files from the response (keep only DICOM files)
        dicom_files = [f for f in uploaded_files if f['is_dicom']]
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'files': dicom_files,  # Only return DICOM files
            'dicom_count': len(dicom_files),
            'total_count': len(uploaded_files),
            'non_dicom_deleted': deleted_count,
            'message': f'Processed {len(uploaded_files)} files. {deleted_count} non-DICOM files were immediately deleted.' if deleted_count > 0 else f'Processed {len(uploaded_files)} files.'
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
    output_session_id = os.urandom(16).hex()
    output_session_dir = os.path.join(app.config['OUTPUT_FOLDER'], output_session_id)
    
    # Track output session timestamp for cleanup
    session_timestamps[output_session_id] = time.time()
    
    # Use safe directory creation
    if not safe_makedirs(output_session_dir):
        return jsonify({'error': 'Failed to create output directory. Permission denied.'}), 500
    
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
                except Exception as e:
                    print(f"Error processing custom rule {tag_str}: {e}")
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
                    output_dir = os.path.dirname(output_file)
                    if not safe_makedirs(output_dir):
                        return jsonify({'error': f'Failed to create output subdirectory: {output_dir}'}), 500
                    
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
            'output_session_id': output_session_id,
            'files': anonymized_files,
            'count': len(anonymized_files)
        })
        
    except Exception as e:
        return jsonify({'error': f'Anonymization failed: {str(e)}', 'traceback': traceback.format_exc()}), 500

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
    """Clean up session files manually"""
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
        if session_id in session_timestamps:
            del session_timestamps[session_id]
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Cleanup failed: {str(e)}'}), 500

@app.route('/status')
def status():
    """Get application status including active sessions"""
    try:
        current_time = time.time()
        active_sessions = []
        
        for session_id, timestamp in session_timestamps.items():
            age_minutes = (current_time - timestamp) / 60
            active_sessions.append({
                'session_id': session_id,
                'created': datetime.datetime.fromtimestamp(timestamp).isoformat(),
                'age_minutes': round(age_minutes, 2),
                'expires_in_minutes': round(10 - age_minutes, 2) if age_minutes < 10 else 0
            })
        
        return jsonify({
            'active_sessions': len(active_sessions),
            'sessions': active_sessions,
            'upload_folder': app.config['UPLOAD_FOLDER'],
            'output_folder': app.config['OUTPUT_FOLDER']
        })
    except Exception as e:
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 1GB.'}), 413

if __name__ == '__main__':
    print("Starting DICOM Anonymizer Web Application...")
    print(f"Upload folder: {UPLOAD_FOLDER}")
    print(f"Output folder: {OUTPUT_FOLDER}")
    print("🚀 Features enabled:")
    print("  - Files without extensions accepted")
    print("  - Automatic cleanup after 10 minutes")
    print("  - Content-based DICOM detection")
    print("Navigate to http://localhost:5000 in your web browser")
    app.run(host='0.0.0.0', port=5000, debug=True)
