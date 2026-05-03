#pragma once
#include <string>
#include <vector>
#include <functional>
#include <optional>

// Callback fired when progress updates: (tested_count, found_word)
using ProgressCb = std::function<void(uint64_t, const std::string&)>;

struct CrackResult {
    bool        found    = false;
    std::string plaintext;
    uint64_t    attempts = 0;
    double      elapsed_s = 0.0;
};

// Dictionary attack: hash each word in the wordlist and compare.
// algo: "md5", "sha1", or "sha256".
CrackResult crack_dict(const std::string& target_hash,
                       const std::string& algo,
                       const std::vector<std::string>& wordlist,
                       const ProgressCb& cb = nullptr);

// Brute-force attack over the given charset up to max_len characters.
CrackResult crack_brute(const std::string& target_hash,
                        const std::string& algo,
                        const std::string& charset,
                        int max_len,
                        const ProgressCb& cb = nullptr);
