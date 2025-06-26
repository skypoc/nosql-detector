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

