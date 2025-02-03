#!/usr/bin/env python3
"""
Security Protocol Testing Framework - Python Automation
Automates test execution, result validation, and reporting

INTERVIEW: "Why use Python for automation?"
- Rapid development and easy maintenance
- Excellent libraries for parsing, reporting, CI/CD integration
- Easy to extend with new test scenarios
"""

import subprocess
import json
import os
import sys
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

# ============================================
# DATA STRUCTURES
# ============================================

class TestStatus(Enum):
    """Mirror of C++ TestStatus enum"""
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"

@dataclass
class TestResult:
    """Holds individual test result data"""
    name: str
    status: TestStatus
    message: str
    duration_ms: float

@dataclass
class TestSuiteResult:
    """Holds complete suite results"""
    suite_name: str
    results: List[TestResult]
    timestamp: datetime
    
    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.PASSED)
    
    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.FAILED)
    
    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.ERROR)
    
    @property
    def total_time_ms(self) -> float:
        return sum(r.duration_ms for r in self.results)
    
    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return (self.passed_count / len(self.results)) * 100

# ============================================
# TEST RUNNER CLASS
# ============================================

class SecurityTestRunner:
    """
    Main automation class that:
    1. Compiles C++ tests
    2. Executes test binary
    3. Parses results
    4. Generates reports
    
    INTERVIEW TIP: This demonstrates "test automation" from JD
    """
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.cpp_dir = self.project_root / "cpp"
        self.logs_dir = self.project_root / "logs"
        self.config_dir = self.project_root / "python" / "config"
        
        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        
    def compile_tests(self) -> bool:
        """
        Compile C++ test code
        
        INTERVIEW: "How did you integrate C++ and Python?"
        Answer: Python orchestrates compilation and execution,
               C++ does the actual cryptographic testing
        """
        print("\n[*] Compiling C++ test framework...")
        
        # Build command
        compile_cmd = [
            "g++",
            "-o", str(self.cpp_dir / "bin" / "test_runner"),
            str(self.cpp_dir / "src" / "main.cpp"),
            str(self.cpp_dir / "src" / "crypto_tests.cpp"),
            str(self.cpp_dir / "src" / "protocol_tests.cpp"),
            "-I", str(self.cpp_dir / "include"),
            "-lssl", "-lcrypto",
            "-std=c++17",
            "-O2"  # Optimization level
        ]
        
        try:
            # Create bin directory
            (self.cpp_dir / "bin").mkdir(exist_ok=True)
            
            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[!] Compilation failed:\n{result.stderr}")
                return False
            
            print("[+] Compilation successful")
            return True
            
        except FileNotFoundError:
            print("[!] g++ not found. Please install GCC.")
            return False
    
    def run_tests(self) -> bool:
        """Execute compiled test binary"""
        print("\n[*] Running tests...")
        
        test_binary = self.cpp_dir / "bin" / "test_runner"
        
        if not test_binary.exists():
            print("[!] Test binary not found. Compile first.")
            return False
        
        try:
            result = subprocess.run(
                [str(test_binary)],
                capture_output=True,
                text=True,
                cwd=str(self.cpp_dir / "bin")
            )
            
            print(result.stdout)
            
            if result.returncode != 0:
                print(f"[!] Test execution had errors:\n{result.stderr}")
                
            return True
            
        except Exception as e:
            print(f"[!] Failed to run tests: {e}")
            return False
    
    def parse_results(self, results_file: str) -> Optional[TestSuiteResult]:
        """
        Parse JSON results from C++ tests
        
        INTERVIEW: "How do you validate test results?"
        Answer: C++ outputs JSON, Python parses and validates structure,
               then applies business rules for pass/fail criteria
        """
        results_path = self.logs_dir / results_file
        
        if not results_path.exists():
            print(f"[!] Results file not found: {results_path}")
            return None
        
        try:
            with open(results_path, 'r') as f:
                data = json.load(f)
            
            results = []
            for r in data['results']:
                results.append(TestResult(
                    name=r['name'],
                    status=TestStatus(r['status']),
                    message=r['message'],
                    duration_ms=r['duration_ms']
                ))
            
            return TestSuiteResult(
                suite_name=data['suite_name'],
                results=results,
                timestamp=datetime.now()
            )
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[!] Failed to parse results: {e}")
            return None
    
    def validate_results(self, suite: TestSuiteResult) -> Dict:
        """
        Apply validation rules to test results
        
        INTERVIEW: "What validation criteria did you use?"
        Answer: 
        - All crypto tests must pass (critical for security)
        - Protocol tests allow warnings but no errors
        - Performance thresholds for time-sensitive operations
        """
        validation = {
            'overall_passed': True,
            'issues': [],
            'warnings': []
        }
        
        # Rule 1: No errors allowed
        if suite.error_count > 0:
            validation['overall_passed'] = False
            validation['issues'].append(
                f"Found {suite.error_count} test errors"
            )
        
        # Rule 2: Pass rate must be 100% for crypto suite
        if 'Crypto' in suite.suite_name and suite.pass_rate < 100:
            validation['overall_passed'] = False
            validation['issues'].append(
                f"Cryptography tests must have 100% pass rate, got {suite.pass_rate:.1f}%"
            )
        
        # Rule 3: Check for slow tests (>100ms is suspicious)
        for result in suite.results:
            if result.duration_ms > 100:
                validation['warnings'].append(
                    f"Slow test: {result.name} took {result.duration_ms:.2f}ms"
                )
        
        # Rule 4: Protocol tests must have >90% pass rate
        if 'Protocol' in suite.suite_name and suite.pass_rate < 90:
            validation['overall_passed'] = False
            validation['issues'].append(
                f"Protocol tests below 90% pass rate: {suite.pass_rate:.1f}%"
            )
        
        return validation
    
    def generate_report(self, suites: List[TestSuiteResult]) -> str:
        """Generate human-readable test report"""
        report = []
        report.append("=" * 60)
        report.append("SECURITY PROTOCOL TESTING FRAMEWORK - AUTOMATED REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        total_tests = 0
        total_passed = 0
        
        for suite in suites:
            total_tests += len(suite.results)
            total_passed += suite.passed_count
            
            report.append(f"\n## {suite.suite_name}")
            report.append("-" * 40)
            report.append(f"Tests Run: {len(suite.results)}")
            report.append(f"Passed: {suite.passed_count}")
            report.append(f"Failed: {suite.failed_count}")
            report.append(f"Errors: {suite.error_count}")
            report.append(f"Pass Rate: {suite.pass_rate:.1f}%")
            report.append(f"Total Time: {suite.total_time_ms:.2f}ms")
            
            # Validation
            validation = self.validate_results(suite)
            if validation['issues']:
                report.append("\n⚠️  ISSUES:")
                for issue in validation['issues']:
                    report.append(f"  - {issue}")
            
            if validation['warnings']:
                report.append("\n⚡ WARNINGS:")
                for warning in validation['warnings']:
                    report.append(f"  - {warning}")
            
            # Failed tests detail
            failed = [r for r in suite.results 
                      if r.status in (TestStatus.FAILED, TestStatus.ERROR)]
            if failed:
                report.append("\n❌ FAILED TESTS:")
                for f in failed:
                    report.append(f"  - {f.name}: {f.message}")
        
        report.append("\n" + "=" * 60)
        report.append("OVERALL SUMMARY")
        report.append(f"Total Tests: {total_tests}")
        report.append(f"Total Passed: {total_passed}")
        report.append(f"Overall Pass Rate: {(total_passed/total_tests)*100:.1f}%")
        report.append("=" * 60)
        
        return "\n".join(report)

# ============================================
# XML CONFIGURATION PARSER
# ============================================

class ConfigParser:
    """
    Parse test configuration from XML
    
    INTERVIEW: "Why XML for config?"
    Answer: Matches JD requirement (C++, Python, XML),
           XML is standard for enterprise configuration,
           Easy to validate with schemas
    """
    
    @staticmethod
    def parse_config(config_file: str) -> Dict:
        """Parse test configuration XML"""
        tree = ET.parse(config_file)
        root = tree.getroot()
        
        config = {
            'test_suites': [],
            'settings': {}
        }
        
        # Parse settings
        settings = root.find('settings')
        if settings is not None:
            config['settings'] = {
                'verbose': settings.findtext('verbose', 'false') == 'true',
                'timeout_ms': int(settings.findtext('timeout_ms', '5000')),
                'retry_count': int(settings.findtext('retry_count', '0'))
            }
        
        # Parse test suites
        for suite in root.findall('.//test_suite'):
            suite_config = {
                'name': suite.get('name'),
                'enabled': suite.get('enabled', 'true') == 'true',
                'tests': []
            }
            
            for test in suite.findall('test'):
                suite_config['tests'].append({
                    'name': test.get('name'),
                    'enabled': test.get('enabled', 'true') == 'true'
                })
            
            config['test_suites'].append(suite_config)
        
        return config

# ============================================
# MAIN EXECUTION
# ============================================

def main():
    """Main entry point for test automation"""
    parser = argparse.ArgumentParser(
        description='Security Protocol Testing Framework - Automation'
    )
    parser.add_argument(
        '--compile', action='store_true',
        help='Compile C++ tests before running'
    )
    parser.add_argument(
        '--config', type=str,
        help='Path to XML configuration file'
    )
    parser.add_argument(
        '--report-only', action='store_true',
        help='Only generate report from existing results'
    )
    parser.add_argument(
        '--output', type=str, default='test_report.txt',
        help='Output file for report'
    )
    
    args = parser.parse_args()
    
    # Determine project root (assuming script is in python/automation/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent
    
    runner = SecurityTestRunner(str(project_root))
    
    # Compile if requested
    if args.compile:
        if not runner.compile_tests():
            print("[!] Compilation failed. Exiting.")
            sys.exit(1)
    
    # Run tests unless report-only
    if not args.report_only:
        if not runner.run_tests():
            print("[!] Test execution failed.")
            sys.exit(1)
    
    # Parse results
    suites = []
    for results_file in ['crypto_results.json', 'protocol_results.json']:
        suite = runner.parse_results(results_file)
        if suite:
            suites.append(suite)
    
    if not suites:
        print("[!] No results found to report on.")
        sys.exit(1)
    
    # Generate and save report
    report = runner.generate_report(suites)
    print(report)
    
    report_path = runner.logs_dir / args.output
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"\n[+] Report saved to: {report_path}")
    
    # Exit with appropriate code
    all_passed = all(
        runner.validate_results(s)['overall_passed'] 
        for s in suites
    )
    sys.exit(0 if all_passed else 1)

if __name__ == '__main__':
    main()