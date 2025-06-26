# NoSQL Injection Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Made by skypoc](https://img.shields.io/badge/made%20by-skypoc-red.svg)](https://github.com/skypoc)

A comprehensive tool for detecting NoSQL injection vulnerabilities in web applications, with a focus on MongoDB-based systems.

## Features

- **Multiple Detection Methods**
  - Boolean-based blind injection
  - Time-based blind injection
  - Error-based injection
  - JavaScript injection ($where)

- **Smart Detection Engine**
  - Automatic endpoint discovery
  - Parameter identification
  - Baseline comparison
  - Confidence scoring

- **Evasion Techniques**
  - User-Agent randomization
  - Request delay variance
  - Payload encoding
  - Rate limiting

- **Comprehensive Reporting**
  - JSON format reports
  - Vulnerability evidence
  - Security recommendations
  - Detection statistics

## Installation

```bash
# Clone the repository
git clone https://github.com/skypoc/nosql-detector.git
cd nosql-detector

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x nosql-detector.py

```

## Usage

```bash
python nosql-detector.py https://target.com

# Scan with custom configuration
python nosql-detector.py https://target.com -c config.yaml

# Test specific endpoints
python nosql-detector.py https://target.com -e /api/login /api/search

# Verbose output
python nosql-detector.py https://target.com -v

# Custom output file
python nosql-detector.py https://target.com -o results.json

# Adjust timeout and threads
python nosql-detector.py https://target.com --timeout 60 --threads 20

```

## Configuration
```yaml
# Request settings
timeout: 30
max_concurrent_requests: 10
delay_between_requests: 0.5

# Detection methods
detection_methods:
  boolean_based: true
  time_based: true
  error_based: true
  javascript: true

# Custom payloads
payloads:
  custom:
    - {"$where": "this.password.length > 5"}
    - {"$regex": "^admin.*"}
```
## Output Example
```json
{
  "scan_info": {
    "start_time": "2024-01-20T10:30:00",
    "duration": "45.23 seconds",
    "total_requests": 156,
    "requests_per_second": 3.45
  },
  "summary": {
    "total_vulnerabilities": 3,
    "high_confidence_vulnerabilities": 2,
    "vulnerable_endpoints": 2,
    "injection_types_found": ["auth_bypass", "boolean_based"]
  },
  "vulnerabilities": [
    {
      "endpoint": "https://target.com/api/login",
      "parameter": "username",
      "type": "auth_bypass",
      "confidence": 0.9,
      "payload": {"$ne": null},
      "evidence": "Authentication bypass successful"
    }
  ]
}
```
## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Author
Made with ❤️ by skypoc

## Disclaimer
This tool is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. The author assumes no liability for misuse of this tool.




