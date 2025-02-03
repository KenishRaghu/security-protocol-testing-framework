# Security Protocol Testing Framework - Makefile
#
# INTERVIEW: "How do you build and run the project?"
# Answer: Just run 'make' to build, 'make test' to run tests
#
# Usage:
#   make          - Build the test framework
#   make test     - Run all tests
#   make clean    - Remove build artifacts
#   make full     - Clean, build, and test

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = cpp/src
INC_DIR = cpp/include
BIN_DIR = cpp/bin
LOG_DIR = logs

# Source files
SOURCES = $(SRC_DIR)/main.cpp \
          $(SRC_DIR)/crypto_tests.cpp \
          $(SRC_DIR)/protocol_tests.cpp

# Target binary
TARGET = $(BIN_DIR)/test_runner

# Default target
all: setup $(TARGET)
	@echo "[+] Build complete!"

# Create directories
setup:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(LOG_DIR)

# Build the test runner
$(TARGET): $(SOURCES)
	@echo "[*] Compiling C++ test framework..."
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) -o $@ $^ $(LDFLAGS)
	@echo "[+] Binary created: $@"

# Run tests
test: $(TARGET)
	@echo "[*] Running tests..."
	@cd $(BIN_DIR) && ./test_runner
	@echo "[*] Running Python automation..."
	python3 python/automation/test_runner.py --report-only

# Run with Python compilation
full-test: clean all
	@echo "[*] Running full test suite with Python automation..."
	python3 python/automation/test_runner.py --compile

# Clean build artifacts
clean:
	@echo "[*] Cleaning..."
	rm -rf $(BIN_DIR)/*
	rm -rf $(LOG_DIR)/*.json
	rm -rf $(LOG_DIR)/*.txt
	@echo "[+] Clean complete"

# Full rebuild and test
full: clean all test

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "[*] Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y g++ libssl-dev python3 python3-pip
	@echo "[+] Dependencies installed"

# Help
help:
	@echo "Security Protocol Testing Framework"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the test framework (default)"
	@echo "  test         - Run all tests"
	@echo "  full-test    - Clean, build, and run with Python automation"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install required dependencies"
	@echo "  help         - Show this help message"

.PHONY: all setup test clean full install-deps help full-test