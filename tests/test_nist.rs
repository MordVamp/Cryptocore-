// use only $cargo test 
use cryptocore::core::crypto::csprng::Csprng;
use nistrs::prelude::*;

const SAMPLE_SIZE: usize = 6_000_000; // 6 million bits for NIST (minimum requirement)
const NIST_THRESHOLD: f64 = 0.01;

#[test]
fn test_csprng_nist_full() {
    println!("Generating {} bits for NIST tests...", SAMPLE_SIZE);
    
    // Generate test data using your CSPRNG
    let random_data = Csprng::generate_random_bytes(SAMPLE_SIZE / 8)
        .expect("Failed to generate random bytes");
    
    let data = BitsData::from_binary(random_data);
    let mut passed = 0;
    let total_tests = 9;
    
    println!("Running NIST statistical tests...");

    // Frequency Test
    let (res, p) = frequency_test(&data);
    println!("Frequency Test: p = {:.6} {}", p, if res { "PASS" } else { "FAIL" });
    if res && p >= NIST_THRESHOLD { passed += 1; }

    // Block Frequency Test
    match block_frequency_test(&data, 128) {
        Ok((res, p)) => {
            println!("Block Frequency Test: p = {:.6} {}", p, if res { "PASS" } else { "FAIL" });
            if res && p >= NIST_THRESHOLD { passed += 1; }
        }
        Err(e) => panic!("Block Frequency test error: {}", e),
    }

    // Cumulative Sums Test (both directions)
    for (i, (res, p)) in cumulative_sums_test(&data).into_iter().enumerate() {
        println!("Cumulative Sums Test {}: p = {:.6} {}", i, p, if res { "PASS" } else { "FAIL" });
        if res && p >= NIST_THRESHOLD { passed += 1; }
    }

    // Runs Test
    let (res, p) = runs_test(&data);
    println!("Runs Test: p = {:.6} {}", p, if res { "PASS" } else { "FAIL" });
    if res && p >= NIST_THRESHOLD { passed += 1; }

    // Longest Run Test
    match longest_run_of_ones_test(&data) {
        Ok((res, p)) => {
            println!("Longest Run Test: p = {:.6} {}", p, if res { "PASS" } else { "FAIL" });
            if res && p >= NIST_THRESHOLD { passed += 1; }
        }
        Err(e) => panic!("Longest Run test error: {}", e),
    }

    // FFT Test
    let (res, p) = fft_test(&data);
    println!("FFT Test: p = {:.6} {}", p, if res { "PASS" } else { "FAIL" });
    if res && p >= NIST_THRESHOLD { passed += 1; }

    // Rank Test
    match rank_test(&data) {
        Ok((res, p)) => {
            println!("Rank Test: p = {:.6} {}", p, if res { "PASS" } else { "FAIL" });
            if res && p >= NIST_THRESHOLD { passed += 1; }
        }
        Err(e) => panic!("Rank test error: {}", e),
    }

let serial_result = serial_test(&data, 16);
println!("Serial Test: p1 = {:.6}, p2 = {:.6}", serial_result[0].1, serial_result[1].1);
if serial_result[0].1 >= NIST_THRESHOLD && serial_result[1].1 >= NIST_THRESHOLD { 
    passed += 1; 
}
    println!("NIST Test Results: {}/{} tests passed", passed, total_tests);
    
    // NIST success criteria: At least 8/9 tests should pass for cryptographic use
    assert!(
        passed >= 8, 
        "NIST tests failed: only {}/{} tests passed. Minimum 8 required for cryptographic RNG.", 
        passed, total_tests
    );
}

#[test]
fn test_key_uniqueness() {
    println!("Testing key uniqueness...");
    let mut key_set = std::collections::HashSet::new();
    
    for i in 0..1000 {
        let key = Csprng::generate_random_bytes(16)
            .expect("Failed to generate random key");
        let key_hex = hex::encode(&key);
        
        assert!(
            !key_set.contains(&key_hex),
            "Duplicate key found at iteration {}: {}",
            i, key_hex
        );
        
        key_set.insert(key_hex);
    }
    
    println!("Successfully generated {} unique keys", key_set.len());
}

#[test]
fn test_nist_data_generation() {
    use std::fs::File;
    use std::io::Write;
    
    println!("Generating 10MB test data for external NIST suite...");
    
    let total_size = 10_000_000; // 10MB
    let mut file = File::create("nist_test_data.bin")
        .expect("Failed to create test data file");
    
    let chunk_size = 4096;
    let mut bytes_written = 0;
    
    while bytes_written < total_size {
        let current_chunk_size = std::cmp::min(chunk_size, total_size - bytes_written);
        let random_chunk = Csprng::generate_random_bytes(current_chunk_size)
            .expect("Failed to generate random data");
        
        file.write_all(&random_chunk)
            .expect("Failed to write test data");
        
        bytes_written += current_chunk_size;
    }
    
    println!("Generated {} bytes for NIST STS in 'nist_test_data.bin'", bytes_written);
    
    // Instructions for running external NIST STS
    println!("\nTo run external NIST Statistical Test Suite:");
    println!("1. Download NIST STS from: https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software");
    println!("2. Compile the C version");
    println!("3. Run: ./assess 10000000");
    println!("4. Follow prompts to specify 'nist_test_data.bin'");
    println!("5. Check results in generated reports");
}