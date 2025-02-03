/*
 * Security Protocol Testing
 * Simulates and validates TLS handshake and protocol interactions
 * 
 * INTERVIEW: "Explain the TLS handshake"
 * 1. Client Hello: Client sends supported cipher suites, random number
 * 2. Server Hello: Server picks cipher suite, sends certificate
 * 3. Key Exchange: They agree on a shared secret
 * 4. Finished: Both verify the handshake wasn't tampered with
 */

#include <iostream>
#include <cstring>
#include <vector>
#include <ctime>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "test_framework.h"

namespace SecurityTest {
namespace ProtocolTests {

/*
 * ============================================
 * TLS HANDSHAKE SIMULATION
 * ============================================
 * 
 * We simulate the protocol messages to test:
 * - Correct message format
 * - Proper state transitions
 * - Error handling for malformed messages
 */

// TLS Message Types
enum class TLSMessageType : uint8_t {
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    CERTIFICATE = 11,
    KEY_EXCHANGE = 12,
    FINISHED = 20,
    ALERT = 21
};

// TLS Alert Levels
enum class AlertLevel : uint8_t {
    WARNING = 1,
    FATAL = 2
};

// Simulated TLS Message structure
struct TLSMessage {
    TLSMessageType type;
    uint16_t length;
    std::vector<uint8_t> data;
    
    TLSMessage(TLSMessageType t) : type(t), length(0) {}
};

// Simulated Client Hello
struct ClientHello {
    uint16_t version;              // TLS version (0x0303 = TLS 1.2)
    uint8_t random[32];            // Client random (for key derivation)
    std::vector<uint16_t> cipherSuites;  // Supported cipher suites
    
    ClientHello() : version(0x0303) {
        RAND_bytes(random, 32);
        // Add common cipher suites
        cipherSuites.push_back(0x1301);  // TLS_AES_128_GCM_SHA256
        cipherSuites.push_back(0x1302);  // TLS_AES_256_GCM_SHA384
        cipherSuites.push_back(0xC02F);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    }
    
    // Serialize to bytes (for transmission)
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        
        // Version
        data.push_back((version >> 8) & 0xFF);
        data.push_back(version & 0xFF);
        
        // Random
        for (int i = 0; i < 32; i++) {
            data.push_back(random[i]);
        }
        
        // Cipher suites length
        uint16_t cs_len = cipherSuites.size() * 2;
        data.push_back((cs_len >> 8) & 0xFF);
        data.push_back(cs_len & 0xFF);
        
        // Cipher suites
        for (uint16_t cs : cipherSuites) {
            data.push_back((cs >> 8) & 0xFF);
            data.push_back(cs & 0xFF);
        }
        
        return data;
    }
};

// Simulated Server Hello
struct ServerHello {
    uint16_t version;
    uint8_t random[32];
    uint16_t selectedCipherSuite;
    
    ServerHello() : version(0x0303), selectedCipherSuite(0) {
        RAND_bytes(random, 32);
    }
    
    // Parse from bytes (received from server)
    bool parse(const std::vector<uint8_t>& data) {
        if (data.size() < 36) return false;  // Minimum size check
        
        version = (data[0] << 8) | data[1];
        memcpy(random, &data[2], 32);
        selectedCipherSuite = (data[34] << 8) | data[35];
        
        return true;
    }
};

// TLS State Machine
// INTERVIEW: "How do you test protocol state transitions?"
enum class TLSState {
    INITIAL,
    CLIENT_HELLO_SENT,
    SERVER_HELLO_RECEIVED,
    CERTIFICATE_RECEIVED,
    KEY_EXCHANGE_DONE,
    HANDSHAKE_COMPLETE,
    ERROR
};

class TLSStateMachine {
private:
    TLSState currentState;
    std::string lastError;
    
public:
    TLSStateMachine() : currentState(TLSState::INITIAL) {}
    
    // Attempt state transition
    bool transition(TLSMessageType messageType) {
        switch (currentState) {
            case TLSState::INITIAL:
                if (messageType == TLSMessageType::CLIENT_HELLO) {
                    currentState = TLSState::CLIENT_HELLO_SENT;
                    return true;
                }
                break;
                
            case TLSState::CLIENT_HELLO_SENT:
                if (messageType == TLSMessageType::SERVER_HELLO) {
                    currentState = TLSState::SERVER_HELLO_RECEIVED;
                    return true;
                }
                break;
                
            case TLSState::SERVER_HELLO_RECEIVED:
                if (messageType == TLSMessageType::CERTIFICATE) {
                    currentState = TLSState::CERTIFICATE_RECEIVED;
                    return true;
                }
                break;
                
            case TLSState::CERTIFICATE_RECEIVED:
                if (messageType == TLSMessageType::KEY_EXCHANGE) {
                    currentState = TLSState::KEY_EXCHANGE_DONE;
                    return true;
                }
                break;
                
            case TLSState::KEY_EXCHANGE_DONE:
                if (messageType == TLSMessageType::FINISHED) {
                    currentState = TLSState::HANDSHAKE_COMPLETE;
                    return true;
                }
                break;
                
            default:
                break;
        }
        
        lastError = "Invalid state transition";
        currentState = TLSState::ERROR;
        return false;
    }
    
    TLSState getState() const { return currentState; }
    std::string getError() const { return lastError; }
};

/*
 * ============================================
 * PROTOCOL TEST CASES
 * ============================================
 */

// Test 1: Valid Handshake Flow
bool testValidHandshakeFlow() {
    TLSStateMachine sm;
    
    // Simulate correct handshake sequence
    if (!sm.transition(TLSMessageType::CLIENT_HELLO)) return false;
    if (!sm.transition(TLSMessageType::SERVER_HELLO)) return false;
    if (!sm.transition(TLSMessageType::CERTIFICATE)) return false;
    if (!sm.transition(TLSMessageType::KEY_EXCHANGE)) return false;
    if (!sm.transition(TLSMessageType::FINISHED)) return false;
    
    return sm.getState() == TLSState::HANDSHAKE_COMPLETE;
}

// Test 2: Out-of-Order Message Rejected
// INTERVIEW: "How do you test protocol violations?"
bool testOutOfOrderMessageRejected() {
    TLSStateMachine sm;
    
    // Send CLIENT_HELLO
    sm.transition(TLSMessageType::CLIENT_HELLO);
    
    // Try to send FINISHED before other messages - should fail!
    bool invalidTransition = sm.transition(TLSMessageType::FINISHED);
    
    // Test passes if the invalid transition was rejected
    return !invalidTransition && sm.getState() == TLSState::ERROR;
}

// Test 3: Client Hello Serialization
bool testClientHelloSerialization() {
    ClientHello hello;
    std::vector<uint8_t> serialized = hello.serialize();
    
    // Check minimum expected size
    // 2 (version) + 32 (random) + 2 (cs length) + 6 (3 cipher suites)
    if (serialized.size() < 42) return false;
    
    // Check version is correct
    uint16_t version = (serialized[0] << 8) | serialized[1];
    if (version != 0x0303) return false;
    
    return true;
}

// Test 4: Server Hello Parsing
bool testServerHelloParsing() {
    // Create fake server response
    std::vector<uint8_t> fakeResponse;
    
    // Version (TLS 1.2)
    fakeResponse.push_back(0x03);
    fakeResponse.push_back(0x03);
    
    // Random (32 bytes of zeros for test)
    for (int i = 0; i < 32; i++) {
        fakeResponse.push_back(0x00);
    }
    
    // Selected cipher suite
    fakeResponse.push_back(0xC0);
    fakeResponse.push_back(0x2F);
    
    ServerHello hello;
    if (!hello.parse(fakeResponse)) return false;
    
    // Verify parsing
    if (hello.version != 0x0303) return false;
    if (hello.selectedCipherSuite != 0xC02F) return false;
    
    return true;
}

// Test 5: Invalid Message Length Handling
// INTERVIEW: "How do you test for buffer overflows?"
bool testInvalidMessageLengthHandling() {
    // Create truncated message (less than minimum size)
    std::vector<uint8_t> truncatedMessage = {0x03, 0x03};  // Only 2 bytes
    
    ServerHello hello;
    // Parser should reject this and return false
    bool parseResult = hello.parse(truncatedMessage);
    
    // Test passes if parsing correctly failed
    return !parseResult;
}

// Test 6: Cipher Suite Negotiation
// INTERVIEW: "How is cipher suite negotiation tested?"
bool testCipherSuiteNegotiation() {
    ClientHello clientHello;
    
    // Verify client offers expected cipher suites
    bool hasAES128 = false, hasAES256 = false;
    
    for (uint16_t cs : clientHello.cipherSuites) {
        if (cs == 0x1301) hasAES128 = true;
        if (cs == 0x1302) hasAES256 = true;
    }
    
    // Client must offer both AES-128 and AES-256 options
    return hasAES128 && hasAES256;
}

// Test 7: Random Number Generation Quality
// INTERVIEW: "How do you verify randomness in protocols?"
bool testRandomNumberQuality() {
    ClientHello hello1, hello2;
    
    // Two hellos should have different randoms
    bool different = false;
    for (int i = 0; i < 32; i++) {
        if (hello1.random[i] != hello2.random[i]) {
            different = true;
            break;
        }
    }
    
    if (!different) return false;
    
    // Check that random isn't all zeros
    bool hasNonZero = false;
    for (int i = 0; i < 32; i++) {
        if (hello1.random[i] != 0) {
            hasNonZero = true;
            break;
        }
    }
    
    return hasNonZero;
}

// Register all protocol tests
void registerProtocolTests(TestSuite& suite) {
    suite.addTest(TestCase(
        "Valid Handshake Flow",
        "Verify complete TLS handshake state transitions",
        testValidHandshakeFlow
    ));
    
    suite.addTest(TestCase(
        "Out-of-Order Message Rejected",
        "Verify protocol rejects messages in wrong order",
        testOutOfOrderMessageRejected
    ));
    
    suite.addTest(TestCase(
        "Client Hello Serialization",
        "Verify Client Hello message format",
        testClientHelloSerialization
    ));
    
    suite.addTest(TestCase(
        "Server Hello Parsing",
        "Verify Server Hello message parsing",
        testServerHelloParsing
    ));
    
    suite.addTest(TestCase(
        "Invalid Message Length Handling",
        "Verify truncated messages are rejected",
        testInvalidMessageLengthHandling
    ));
    
    suite.addTest(TestCase(
        "Cipher Suite Negotiation",
        "Verify client offers required cipher suites",
        testCipherSuiteNegotiation
    ));
    
    suite.addTest(TestCase(
        "Random Number Quality",
        "Verify random values are properly generated",
        testRandomNumberQuality
    ));
}

} // namespace ProtocolTests
} // namespace SecurityTest

