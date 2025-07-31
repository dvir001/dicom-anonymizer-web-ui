#!/usr/bin/env python3
"""
DICOM Anonymizer Enhancement Script
This script provides the code changes needed to:
1. Allow files without extensions
2. Implement automatic 24-hour cleanup
"""

print("?? DICOM Anonymizer Enhancement Instructions")
print("=" * 60)
print()

print("?? Changes needed for app.py:")
print("-" * 30)

app_changes = '''
# Key changes to make in app.py:

1. IMPORT ADDITIONS (add these imports at the top):
   import threading
   import time  
   import datetime

2. MODIFY allowed_file function:
   def allowed_file(filename):
       """Allow all files regardless of extension"""
       return True  # Accept all files

3. ADD SESSION TRACKING (after app config):
   # File tracking for automatic cleanup
   session_timestamps = {}

4. ADD CLEANUP THREAD FUNCTION (before routes):
   def cleanup_old_sessions():
       """Background task to clean up sessions older than 24 hours"""
       while True:
           try:
               current_time = time.time()
               sessions_to_remove = []
               
               for session_id, timestamp in session_timestamps.items():
                   # Check if session is older than 24 hours (86400 seconds)
                   if current_time - timestamp > 86400:
                       sessions_to_remove.append(session_id)
               
               # Clean up old sessions
               for session_id in sessions_to_remove:
                   try:
                       # Clean up upload session
                       upload_session = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
                       if os.path.exists(upload_session):
                           shutil.rmtree(upload_session)
                           print(f"??? Cleaned up old upload session: {session_id}")
                       
                       # Clean up output session  
                       output_session = os.path.join(app.config['OUTPUT_FOLDER'], session_id)
                       if os.path.exists(output_session):
                           shutil.rmtree(output_session)
                           print(f"??? Cleaned up old output session: {session_id}")
                       
                       # Clean up zip files
                       zip_file = os.path.join(app.config['OUTPUT_FOLDER'], f'{session_id}_anonymized.zip')
                       if os.path.exists(zip_file):
                           os.remove(zip_file)
                           print(f"??? Cleaned up old zip file: {session_id}")
                       
                       # Remove from tracking
                       del session_timestamps[session_id]
                       
                   except Exception as e:
                       print(f"? Error cleaning up session {session_id}: {e}")
               
               # Sleep for 1 hour before next cleanup check
               time.sleep(3600)
               
           except Exception as e:
               print(f"? Error in cleanup thread: {e}")
               time.sleep(3600)

5. START CLEANUP THREAD (after the function):
   # Start the cleanup thread
   cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
   cleanup_thread.start()

6. MODIFY upload_files function:
   - Add session tracking: session_timestamps[session_id] = time.time()
   - Change file validation: if file: (instead of if file and allowed_file...)
   - Add better ZIP detection using content instead of extension
   - Include total_count in response

7. MODIFY anonymize_files function:
   - Add: session_timestamps[output_session_id] = time.time()

8. ADD STATUS ENDPOINT (new route):
   @app.route('/status')
   def status():
       """Get application status including active sessions"""
       try:
           current_time = time.time()
           active_sessions = []
           
           for session_id, timestamp in session_timestamps.items():
               age_hours = (current_time - timestamp) / 3600
               active_sessions.append({
                   'session_id': session_id,
                   'created': datetime.datetime.fromtimestamp(timestamp).isoformat(),
                   'age_hours': round(age_hours, 2),
                   'expires_in_hours': round(24 - age_hours, 2) if age_hours < 24 else 0
               })
           
           return jsonify({
               'active_sessions': len(active_sessions),
               'sessions': active_sessions,
               'upload_folder': app.config['UPLOAD_FOLDER'],
               'output_folder': app.config['OUTPUT_FOLDER']
           })
       except Exception as e:
           return jsonify({'error': f'Status check failed: {str(e)}'}), 500
'''

print(app_changes)
print()

print("?? Changes needed for templates/index.html:")
print("-" * 40)

html_changes = '''
# Key changes to make in templates/index.html:

1. REMOVE FILE TYPE RESTRICTIONS:
   - Remove accept=".dcm,.dicom,.ima,.zip" from input element
   - Change to: <input type="file" id="fileInput" multiple style="display: none;">

2. UPDATE UI TEXT:
   - Change upload area text to mention "All file types accepted"
   - Add information about content-based DICOM detection
   - Add auto-cleanup notice

3. ENHANCE FILE DISPLAY:
   - Add visual indicators for DICOM vs non-DICOM files
   - Show file icons and better styling
   - Display cleanup notice

4. IMPROVE STATUS MESSAGES:
   - Add emojis for better UX
   - Show total vs DICOM file counts
   - Add warning for no DICOM files detected

5. ADD DRAG & DROP IMPROVEMENTS:
   - Better visual feedback during drag operations
   - Proper event handling for all file types
'''

print(html_changes)
print()

print("?? Docker Configuration:")
print("-" * 25)

docker_info = '''
# Your current Docker setup should work, but ensure:

1. Dockerfile has proper permissions (already addressed in previous fix)
2. docker-compose.yml uses volumes for persistence
3. Container can handle threading (should work with current setup)

# To rebuild and test:
docker-compose down
docker-compose up --build

# To check cleanup is working:
# Visit http://localhost:5000/status to see active sessions
'''

print(docker_info)
print()

print("? Testing the Changes:")
print("-" * 25)

testing_info = '''
# Test scenarios:

1. Upload DICOM files WITHOUT extensions
2. Upload regular files (should show as "Not DICOM")
3. Upload ZIP files containing DICOM files
4. Check http://localhost:5000/status for session tracking
5. Wait 24+ hours or modify time check for faster testing

# Features you'll have:
? Accept all file types (no extension required)
? Content-based DICOM detection
? Automatic 24-hour cleanup
? Session tracking and status monitoring
? Better error handling and user feedback
? Enhanced UI with file type indicators
'''

print(testing_info)
print()

print("?? Quick Implementation Steps:")
print("-" * 35)

steps = '''
1. Apply the app.py changes above
2. Apply the templates/index.html changes above  
3. Rebuild Docker container: docker-compose up --build
4. Test with files that have no extensions
5. Monitor status at /status endpoint
6. Verify cleanup works (or test with shorter time intervals)
'''

print(steps)
print()
print("?? Your DICOM anonymizer will now accept any file type and auto-cleanup!")