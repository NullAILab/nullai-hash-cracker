#include "cracker.h"
#include "hash.h"

#include <chrono>
#include <functional>
#include <string>
#include <algorithm>

// ---------------------------------------------------------------------------
// Internal: hash dispatcher
// ---------------------------------------------------------------------------

static std::string do_hash(const std::string& algo, const std::string& s) {
    if (algo == "md5")    return md5_hex(s);
    if (algo == "sha1")   return sha1_hex(s);
    if (algo == "sha256") return sha256_hex(s);
    return "";
}

// ---------------------------------------------------------------------------
// Dictionary attack
// ---------------------------------------------------------------------------

CrackResult crack_dict(const std::string& target_hash,
                       const std::string& algo,
                       const std::vector<std::string>& wordlist,
                       const ProgressCb& cb) {
    CrackResult res;
    auto t0 = std::chrono::steady_clock::now();

    // Normalise target to lowercase for comparison
    std::string target = target_hash;
    std::transform(target.begin(), target.end(), target.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    for (const auto& word : wordlist) {
        ++res.attempts;
        std::string h = do_hash(algo, word);
        if (h == target) {
            res.found     = true;
            res.plaintext = word;
            break;
        }
        if (cb && res.attempts % 10000 == 0)
            cb(res.attempts, "");
    }

    auto t1 = std::chrono::steady_clock::now();
    res.elapsed_s = std::chrono::duration<double>(t1 - t0).count();

    if (cb)
        cb(res.attempts, res.found ? res.plaintext : "");

    return res;
}

// ---------------------------------------------------------------------------
// Brute-force attack
// ---------------------------------------------------------------------------

// Iterate over all strings of length `len` over `charset`.
// Calls hash_fn for each candidate; returns true if found.
static bool bf_recurse(const std::string& target,
                       const std::string& algo,
                       const std::string& charset,
                       std::string& current,
                       int remaining,
                       uint64_t& attempts,
                       std::string& found_plain,
                       const ProgressCb& cb) {
    if (remaining == 0) {
        ++attempts;
        if (do_hash(algo, current) == target) {
            found_plain = current;
            return true;
        }
        if (cb && attempts % 100000 == 0)
            cb(attempts, "");
        return false;
    }
    for (char c : charset) {
        current.push_back(c);
        if (bf_recurse(target, algo, charset, current,
                       remaining - 1, attempts, found_plain, cb))
            return true;
        current.pop_back();
    }
    return false;
}

CrackResult crack_brute(const std::string& target_hash,
                        const std::string& algo,
                        const std::string& charset,
                        int max_len,
                        const ProgressCb& cb) {
    CrackResult res;
    auto t0 = std::chrono::steady_clock::now();

    std::string target = target_hash;
    std::transform(target.begin(), target.end(), target.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    for (int len = 1; len <= max_len && !res.found; ++len) {
        std::string current;
        current.reserve(len);
        if (bf_recurse(target, algo, charset, current,
                       len, res.attempts, res.plaintext, cb)) {
            res.found = true;
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    res.elapsed_s = std::chrono::duration<double>(t1 - t0).count();
    if (cb) cb(res.attempts, res.found ? res.plaintext : "");
    return res;
}
