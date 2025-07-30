# DICOM Anonymizer Web Application

This is a web-based version of the DICOM Anonymizer that provides a user-friendly interface for anonymizing DICOM files through a web browser.

## Features

- **Web Interface**: Modern, responsive web interface accessible through any web browser
- **File Upload**: Support for individual DICOM files (.dcm, .dicom, .ima) and ZIP archives
- **Drag & Drop**: Easy file upload with drag and drop functionality
- **Batch Processing**: Process multiple DICOM files at once
- **Privacy Options**: Choose whether to keep or remove private DICOM tags
- **Custom Rules**: Advanced users can define custom anonymization rules for specific DICOM tags
- **Secure Download**: Download anonymized files as a ZIP archive
- **Session Management**: Automatic cleanup of temporary files after processing

## Installation & Setup

1. **Install Flask** (if not already installed):
   ```bash
   pip install flask
   ```

2. **Ensure DICOM Anonymizer is installed**:
   ```bash
   pip install dicom-anonymizer
   ```
   Or if working with the source code:
   ```bash
   pip install -e .
   ```

3. **Run the web application**:
   ```bash
   python app.py
   ```

4. **Open your web browser** and navigate to:
   ```
   http://localhost:5000
   ```

## How to Use

### Step 1: Upload Files
- Click on the upload area or drag and drop your DICOM files
- Supported formats: `.dcm`, `.dicom`, `.ima`, and `.zip` archives
- Maximum file size: 500MB per upload
- The system will automatically detect which files are valid DICOM files

### Step 2: Configure Options
- **Keep Private Tags**: Check this option if you want to preserve private DICOM tags (unchecked by default for maximum anonymization)
- **Custom Rules** (Advanced): Define specific anonymization actions for particular DICOM tags

### Step 3: Start Anonymization
- Click "Start Anonymization" to begin the process
- The system will process all DICOM files using the DICOM standard anonymization rules
- Progress will be shown in real-time

### Step 4: Download Results
- Once complete, download the anonymized files as a ZIP archive
- Files are automatically cleaned up after download

## Technical Details

### Architecture
- **Backend**: Flask web application
- **Frontend**: Modern HTML5/CSS3/JavaScript interface
- **Processing**: Uses the existing `dicomanonymizer` Python package
- **File Handling**: Secure temporary file management with automatic cleanup

### API Endpoints
- `POST /upload` - Upload DICOM files
- `POST /anonymize` - Start anonymization process
- `GET /download/<session_id>` - Download anonymized files
- `GET /cleanup/<session_id>` - Clean up session files

### Security Features
- Secure filename handling
- Session-based file isolation
- Automatic cleanup of temporary files
- File type validation
- Size limits to prevent abuse

### File Structure
```
dicom-anonymizer/
??? app.py                  # Main Flask application
??? templates/
?   ??? index.html         # Web interface template
??? temp_uploads/          # Temporary upload directory (auto-created)
??? temp_outputs/          # Temporary output directory (auto-created)
??? dicomanonymizer/       # Core anonymization library
```

## Anonymization Process

The web application uses the same robust anonymization engine as the command-line version:

1. **Standard Compliance**: Follows DICOM anonymization standards (2023e by default)
2. **Tag Categories**: Different anonymization actions based on tag groups:
   - **D_TAGS**: Replace with dummy values
   - **Z_TAGS**: Empty/zero-length values
   - **X_TAGS**: Complete removal
   - **U_TAGS**: UID replacement
   - And more complex combinations

3. **Private Tags**: Option to keep or remove private tags
4. **Custom Rules**: Override default behavior for specific tags

## Troubleshooting

### Common Issues

1. **"No module named 'flask'"**
   - Install Flask: `pip install flask`

2. **"No module named 'dicomanonymizer'"**
   - Install the package: `pip install dicom-anonymizer` or `pip install -e .`

3. **"File too large" error**
   - The default limit is 500MB. Large files should be split or processed individually.

4. **Browser compatibility**
   - Use modern browsers (Chrome, Firefox, Safari, Edge)
   - JavaScript must be enabled

### Performance Tips

- For large batches, process files in smaller groups
- ZIP archives are automatically extracted and processed
- Network timeout may occur for very large uploads - use smaller batches

## Development

To modify or extend the web application:

1. **Flask App** (`app.py`): Contains all backend logic
2. **HTML Template** (`templates/index.html`): Frontend interface
3. **CSS/JavaScript**: Embedded in the HTML template for simplicity

### Adding Features

- **Custom Actions**: Extend the `action_map` in the anonymize endpoint
- **File Formats**: Add support for additional formats in `ALLOWED_EXTENSIONS`
- **UI Enhancements**: Modify the HTML template and CSS styles

## License

Same license as the core DICOM Anonymizer project (BSD License).

## Support

For issues related to:
- **Web Interface**: Check browser console for JavaScript errors
- **Anonymization Logic**: Refer to the main DICOM Anonymizer documentation
- **DICOM Standards**: Consult DICOM anonymization specifications

---

**Note**: This web application is designed for local use or trusted network environments. For production deployment, additional security measures should be implemented.