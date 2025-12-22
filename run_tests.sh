#!/bin/bash
# Simple CryptoCore test runner

echo "🚀 Running CryptoCore Tests..."
echo "=============================="

# Build first
echo "Building..."
cargo build --release || { echo "Build failed!"; exit 1; }

# Run tests and show output
echo -e "\nRunning tests..."
echo "================"

# List of test files
tests=(
    "test_gcm"
    "hmac_tests" 
    "cmac_tests"
    "test_kdf"
    "test_nist"
    "integration_tests"
    "modes_tests"
    "openssl_interop_tests"
    "memory_safety"
    "negative_tests"
    "interoperability_tests"
)

total_tests=0
passed_tests=0

for test in "${tests[@]}"; do
    echo -e "\n▸ Testing: $test"
    
    # Run test and capture output
    output=$(cargo test --test "$test" -- --nocapture 2>&1)
    
    # Check if tests passed
    if echo "$output" | grep -q "test result: ok" && \
       echo "$output" | grep -q "0 failed"; then
        echo "  ✅ PASSED"
        ((passed_tests++))
    else
        echo "  ❌ FAILED"
        echo "$output" | grep -A5 -B5 "FAILED\|failed\|error"
    fi
    
    ((total_tests++))
done

# Summary
echo -e "\n📊 SUMMARY"
echo "=========="
echo "Tests passed: $passed_tests/$total_tests"

if [ $passed_tests -eq $total_tests ]; then
    echo "✅ ALL TESTS PASSED!"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    exit 1
fi