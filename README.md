# CyberSentry - Security & Threat Detection

A comprehensive browser extension that monitors browsing for potential threats, phishing attempts, and vulnerabilities.

## Features

- **Real-time Security Analysis**: Analyzes websites as you browse to detect potential security threats
- **Phishing Detection**: Identifies potential phishing websites that may try to steal your information
- **Malware Detection**: Scans for malicious scripts and content that could harm your device
- **Form Security**: Checks if forms are submitting sensitive information securely
- **Privacy Protection**: Detects potential data leakage and cryptocurrency miners
- **Detailed Threat Information**: Provides comprehensive information about detected threats
- **Security Statistics**: Tracks security metrics and threat encounters

## Installation

### Chrome/Edge

1. Download or clone this repository
2. Open Chrome/Edge and navigate to `chrome://extensions` or `edge://extensions`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the extension directory
5. The extension should now be installed and active

### Firefox

1. Download or clone this repository
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on..."
4. Select the `manifest.json` file in the extension directory
5. The extension should now be installed and active

## Usage

- The extension icon will show the security status of the current website
- Click the icon to see detailed security information
- The extension will automatically block dangerous websites and show a warning
- You can customize security settings by clicking the extension icon and going to the Settings tab

## Security Features

- **URL Analysis**: Checks URLs against known phishing and malware domains
- **Content Scanning**: Analyzes page content for suspicious scripts and code
- **Form Security**: Ensures sensitive information is submitted securely
- **Script Monitoring**: Detects potentially harmful scripts like cryptocurrency miners
- **Privacy Protection**: Identifies scripts that may leak your data

## Development

### Project Structure

- `manifest.json`: Extension configuration
- `background.js`: Background service worker for security analysis
- `content.js`: Content script that runs on web pages
- `popup.html/js`: Extension popup UI
- `warning.html`: Warning page for dangerous websites
- `threat_details.html`: Detailed threat information page
- `icons/`: SVG icons for the extension

### Building from Source

1. Clone the repository
2. Make your changes
3. Load the extension as described in the Installation section

## Privacy

CyberSentry respects your privacy:

- No browsing data is sent to external servers
- All security analysis happens locally on your device
- No personal information is collected or shared

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This extension was created to help users browse the web more safely
- Icon designs by [placeholder]
- Special thanks to all contributors

## Contact

For questions, feedback, or issues, please open an issue on the GitHub repository. 