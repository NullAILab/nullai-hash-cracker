#pragma once
#include <string>
#include <cstdint>

// Returns lowercase hex digest for the given input using each algorithm.
std::string md5_hex(const std::string& input);
std::string sha1_hex(const std::string& input);
std::string sha256_hex(const std::string& input);

// Identify which algorithm a hash string likely belongs to based on length.
// Returns "md5", "sha1", "sha256", or "unknown".
std::string identify_hash(const std::string& hex);
