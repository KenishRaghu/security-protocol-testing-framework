/*
 * Security Protocol Testing Framework - Main Entry Point
 * 
 * Compiles and runs all test suites
 * Exports results for Python automation to analyze
 * 
 * BUILD: g++ -o test_runner main.cpp crypto_tests.cpp protocol_tests.cpp \
 *        -lssl -lcrypto -std=c++17
 */

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include "test_framework.h"

// Forward declarations from other files
namespace SecurityTest {
    namespace CryptoTests {
        void registerCryptoTests(TestSuite& suite);
    }
    namespace ProtocolTests {
        void registerProtocolTests(TestSuite& suite);
    }
}

namespace SecurityTest {

// Implementation of TestSuite methods
void TestSuite::runAll() {
    std::cout << "\n========================================\n";
    std::cout << "Running Test Suite: " << suiteName << "\n";
    std::cout << "========================================\n\n";
    
    results.clear();
    
    for (const auto& test : testCases) {
        std::cout << "Running: " << test.name << "... ";
        
        auto start = std::chrono::high_resolution_clock::now();
        
        TestStatus status;
        std::string message;
        
        try {
            bool passed = test.testFunction();
            status = passed ? TestStatus::PASSED : TestStatus::FAILED;
            message = passed ? "Test passed" : "Test failed";
        } catch (const std::exception& e) {
            status = TestStatus::ERROR;
            message = std::string("Exception: ") + e.what();
        } catch (...) {
            status = TestStatus::ERROR;
            message = "Unknown exception";
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        
        results.emplace_back(test.name, status, message, duration);
        
        // Print result
        switch (status) {
            case TestStatus::PASSED:
                std::cout << "PASSED (" << std::fixed << std::setprecision(2) 
                          << duration << "ms)\n";
                break;
            case TestStatus::FAILED:
                std::cout << "FAILED\n";
                std::cout << "  -> " << message << "\n";
                break;
            case TestStatus::ERROR:
                std::cout << "ERROR\n";
                std::cout << "  -> " << message << "\n";
                break;
            default:
                std::cout << "SKIPPED\n";
        }
    }
}

void TestSuite::printSummary() const {
    int passed = 0, failed = 0, errors = 0, skipped = 0;
    double totalTime = 0;
    
    for (const auto& result : results) {
        totalTime += result.executionTimeMs;
        switch (result.status) {
            case TestStatus::PASSED: passed++; break;
            case TestStatus::FAILED: failed++; break;
            case TestStatus::ERROR: errors++; break;
            case TestStatus::SKIPPED: skipped++; break;
        }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "TEST SUMMARY: " << suiteName << "\n";
    std::cout << "========================================\n";
    std::cout << "Total Tests: " << results.size() << "\n";
    std::cout << "Passed:      " << passed << "\n";
    std::cout << "Failed:      " << failed << "\n";
    std::cout << "Errors:      " << errors << "\n";
    std::cout << "Skipped:     " << skipped << "\n";
    std::cout << "Total Time:  " << std::fixed << std::setprecision(2) 
              << totalTime << "ms\n";
    std::cout << "========================================\n";
}

void TestSuite::exportResults(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for export: " << filename << "\n";
        return;
    }
    
    // Export as JSON for Python to parse
    // INTERVIEW: "Why JSON?" - Universal format, Python has built-in parser
    file << "{\n";
    file << "  \"suite_name\": \"" << suiteName << "\",\n";
    file << "  \"results\": [\n";
    
    for (size_t i = 0; i < results.size(); i++) {
        const auto& r = results[i];
        file << "    {\n";
        file << "      \"name\": \"" << r.testName << "\",\n";
        file << "      \"status\": \"";
        switch (r.status) {
            case TestStatus::PASSED: file << "PASSED"; break;
            case TestStatus::FAILED: file << "FAILED"; break;
            case TestStatus::ERROR: file << "ERROR"; break;
            case TestStatus::SKIPPED: file << "SKIPPED"; break;
        }
        file << "\",\n";
        file << "      \"message\": \"" << r.message << "\",\n";
        file << "      \"duration_ms\": " << r.executionTimeMs << "\n";
        file << "    }";
        if (i < results.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    file.close();
    std::cout << "Results exported to: " << filename << "\n";
}

// Utility function implementations
namespace CryptoUtils {
    std::string bytesToHex(const unsigned char* data, size_t len) {
        std::string hex;
        hex.reserve(len * 2);
        const char* hexChars = "0123456789abcdef";
        for (size_t i = 0; i < len; i++) {
            hex.push_back(hexChars[(data[i] >> 4) & 0x0F]);
            hex.push_back(hexChars[data[i] & 0x0F]);
        }
        return hex;
    }
    
    // Constant-time comparison to prevent timing attacks
    // INTERVIEW: This is critical for security! 
    // Regular comparison stops at first difference - attacker can measure time
    bool secureCompare(const unsigned char* a, const unsigned char* b, size_t len) {
        unsigned char result = 0;
        for (size_t i = 0; i < len; i++) {
            result |= a[i] ^ b[i];  // XOR accumulates differences
        }
        return result == 0;  // Only returns after checking ALL bytes
    }
    
    void generateRandomBytes(unsigned char* buffer, size_t len) {
        RAND_bytes(buffer, len);
    }
}

} // namespace SecurityTest

int main(int argc, char* argv[]) {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════╗\n";
    std::cout << "║  Security Protocol Testing Framework     ║\n";
    std::cout << "║  Version 1.0.0                           ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";
    
    // Initialize OpenSSL
    // INTERVIEW: Always initialize crypto libraries properly
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Create and run Cryptography test suite
    SecurityTest::TestSuite cryptoSuite("Cryptography Tests");
    SecurityTest::CryptoTests::registerCryptoTests(cryptoSuite);
    cryptoSuite.runAll();
    cryptoSuite.printSummary();
    cryptoSuite.exportResults("../logs/crypto_results.json");
    
    // Create and run Protocol test suite
    SecurityTest::TestSuite protocolSuite("Protocol Tests");
    SecurityTest::ProtocolTests::registerProtocolTests(protocolSuite);
    protocolSuite.runAll();
    protocolSuite.printSummary();
    protocolSuite.exportResults("../logs/protocol_results.json");
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    std::cout << "\nAll tests completed. Results exported to logs/\n";
    
    return 0;
}