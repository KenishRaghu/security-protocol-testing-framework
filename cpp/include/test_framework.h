/*
 * Security Protocol Testing Framework
 * Header file defining test structures and utilities
 * 
 * INTERVIEW TIP: Be ready to explain why we use header files
 * Answer: Separation of declaration and implementation, 
 *         allows multiple files to use same definitions
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <string>
#include <vector>
#include <chrono>
#include <functional>

namespace SecurityTest {

// Enum for test result status
// INTERVIEW TIP: Enums provide type safety vs plain integers
enum class TestStatus {
    PASSED,
    FAILED,
    SKIPPED,
    ERROR
};

// Structure to hold individual test results
struct TestResult {
    std::string testName;
    TestStatus status;
    std::string message;
    double executionTimeMs;
    
    // Constructor for easy initialization
    TestResult(const std::string& name, TestStatus s, 
               const std::string& msg, double time)
        : testName(name), status(s), message(msg), executionTimeMs(time) {}
};

// Structure for test case definition
struct TestCase {
    std::string name;
    std::string description;
    std::function<bool()> testFunction;  // Function pointer to actual test
    
    TestCase(const std::string& n, const std::string& desc, 
             std::function<bool()> func)
        : name(n), description(desc), testFunction(func) {}
};

// Test Suite class - manages collection of tests
class TestSuite {
private:
    std::string suiteName;
    std::vector<TestCase> testCases;
    std::vector<TestResult> results;
    
public:
    TestSuite(const std::string& name) : suiteName(name) {}
    
    // Add a test case to the suite
    void addTest(const TestCase& test) {
        testCases.push_back(test);
    }
    
    // Run all tests and collect results
    void runAll();
    
    // Get results for reporting
    const std::vector<TestResult>& getResults() const { return results; }
    
    // Print summary to console
    void printSummary() const;
    
    // Export results to file (for Python automation to read)
    void exportResults(const std::string& filename) const;
};

// Utility functions for cryptographic testing
namespace CryptoUtils {
    // Convert bytes to hex string for display
    std::string bytesToHex(const unsigned char* data, size_t len);
    
    // Compare two byte arrays securely (constant-time)
    // INTERVIEW TIP: Why constant-time? Prevents timing attacks!
    bool secureCompare(const unsigned char* a, const unsigned char* b, size_t len);
    
    // Generate random bytes for testing
    void generateRandomBytes(unsigned char* buffer, size_t len);
}

// Assertion macros for cleaner test code
#define ASSERT_TRUE(condition, message) \
    if (!(condition)) { \
        throw std::runtime_error(std::string("Assertion failed: ") + message); \
    }

#define ASSERT_EQUAL(expected, actual, message) \
    if ((expected) != (actual)) { \
        throw std::runtime_error(std::string("Equality assertion failed: ") + message); \
    }

#define ASSERT_BYTES_EQUAL(expected, actual, len, message) \
    if (!CryptoUtils::secureCompare(expected, actual, len)) { \
        throw std::runtime_error(std::string("Bytes comparison failed: ") + message); \
    }

} // namespace SecurityTest

#endif // TEST_FRAMEWORK_H