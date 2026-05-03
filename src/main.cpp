/*
 * main.cpp — Hash Cracker CLI
 *
 * Subcommands:
 *   hash   <algo> <plaintext>         Compute and print a hash
 *   id     <hash>                     Identify hash algorithm by length
 *   dict   <hash> <wordlist.txt>      Dictionary attack
 *   brute  <hash> [options]           Brute-force attack
 *
 * Options for brute:
 *   --charset <chars>   Character set (default: abcdefghijklmnopqrstuvwxyz)
 *   --max-len <n>       Maximum length to try (default: 4)
 *   --algo <name>       Algorithm override (auto-detect by default)
 *
 * Examples:
 *   ./hash-cracker hash md5 "hello"
 *   ./hash-cracker id  5d41402abc4b2a76b9719d911017c592
 *   ./hash-cracker dict 5d41402abc4b2a76b9719d911017c592 rockyou.txt
 *   ./hash-cracker brute 5d41402abc4b2a76b9719d911017c592 --max-len 5
 */

#include "hash.h"
#include "cracker.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include <cstring>

static void usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " <command> [args]\n\n"
        "Commands:\n"
        "  hash  <md5|sha1|sha256> <text>   Compute hash\n"
        "  id    <hash>                      Identify hash type\n"
        "  dict  <hash> <wordlist>           Dictionary attack\n"
        "  brute <hash> [--charset X] [--max-len N] [--algo A]\n\n"
        "Examples:\n"
        "  " << prog << " hash sha256 \"hello world\"\n"
        "  " << prog << " dict 5d41402abc4b2a76b9719d911017c592 rockyou.txt\n"
        "  " << prog << " brute 5d41402abc4b2a76b9719d911017c592 --max-len 5\n";
}

static std::vector<std::string> load_wordlist(const std::string& path) {
    std::vector<std::string> words;
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[!] Cannot open wordlist: " << path << "\n";
        return words;
    }
    std::string line;
    while (std::getline(f, line)) {
        // Strip \r for Windows-style line endings
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            words.push_back(line);
    }
    return words;
}

static void print_result(const CrackResult& r, const std::string& target) {
    if (r.found) {
        std::cout << "[+] CRACKED!\n"
                  << "    Hash      : " << target << "\n"
                  << "    Plaintext : " << r.plaintext << "\n";
    } else {
        std::cout << "[-] Not found.\n";
    }
    std::cout << "    Attempts  : " << r.attempts << "\n"
              << "    Time      : " << std::fixed << std::setprecision(3)
              << r.elapsed_s << "s\n";
    if (r.attempts > 0 && r.elapsed_s > 0)
        std::cout << "    Rate      : "
                  << static_cast<uint64_t>(r.attempts / r.elapsed_s)
                  << " hash/s\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    std::string cmd = argv[1];

    // ── hash ──────────────────────────────────────────────────
    if (cmd == "hash") {
        if (argc < 4) { std::cerr << "Usage: hash <algo> <text>\n"; return 1; }
        std::string algo = argv[2];
        std::string text = argv[3];
        std::string h;
        if      (algo == "md5")    h = md5_hex(text);
        else if (algo == "sha1")   h = sha1_hex(text);
        else if (algo == "sha256") h = sha256_hex(text);
        else { std::cerr << "[!] Unknown algo: " << algo << "\n"; return 1; }
        std::cout << h << "\n";
        return 0;
    }

    // ── id ────────────────────────────────────────────────────
    if (cmd == "id") {
        if (argc < 3) { std::cerr << "Usage: id <hash>\n"; return 1; }
        std::cout << identify_hash(argv[2]) << "\n";
        return 0;
    }

    // ── dict ──────────────────────────────────────────────────
    if (cmd == "dict") {
        if (argc < 4) { std::cerr << "Usage: dict <hash> <wordlist>\n"; return 1; }
        std::string target = argv[2];
        std::string algo   = identify_hash(target);
        if (algo == "unknown") {
            std::cerr << "[!] Cannot identify hash type (length: " << target.size() << ")\n";
            return 1;
        }
        std::cout << "[*] Target : " << target << " (" << algo << ")\n";

        auto words = load_wordlist(argv[3]);
        if (words.empty()) return 1;
        std::cout << "[*] Loaded " << words.size() << " words\n";

        auto cb = [](uint64_t n, const std::string&){
            std::cout << "\r[*] Tested: " << n << "   " << std::flush;
        };
        auto r = crack_dict(target, algo, words, cb);
        std::cout << "\n";
        print_result(r, target);
        return r.found ? 0 : 1;
    }

    // ── brute ─────────────────────────────────────────────────
    if (cmd == "brute") {
        if (argc < 3) { std::cerr << "Usage: brute <hash> [options]\n"; return 1; }
        std::string target  = argv[2];
        std::string algo    = identify_hash(target);
        std::string charset = "abcdefghijklmnopqrstuvwxyz";
        int max_len         = 4;

        for (int i = 3; i < argc; ++i) {
            if (std::strcmp(argv[i], "--charset") == 0 && i+1 < argc)
                charset = argv[++i];
            else if (std::strcmp(argv[i], "--max-len") == 0 && i+1 < argc)
                max_len = std::stoi(argv[++i]);
            else if (std::strcmp(argv[i], "--algo") == 0 && i+1 < argc)
                algo = argv[++i];
        }

        if (algo == "unknown") {
            std::cerr << "[!] Unknown hash type — use --algo to specify\n";
            return 1;
        }

        uint64_t total = 0;
        for (int l = 1; l <= max_len; ++l) {
            uint64_t pw = 1;
            for (int j = 0; j < l; ++j) pw *= charset.size();
            total += pw;
        }

        std::cout << "[*] Target    : " << target << " (" << algo << ")\n"
                  << "[*] Charset   : " << charset << "\n"
                  << "[*] Max length: " << max_len << "\n"
                  << "[*] Keyspace  : ~" << total << "\n";

        auto cb = [](uint64_t n, const std::string&){
            std::cout << "\r[*] Tested: " << n << "   " << std::flush;
        };
        auto r = crack_brute(target, algo, charset, max_len, cb);
        std::cout << "\n";
        print_result(r, target);
        return r.found ? 0 : 1;
    }

    std::cerr << "[!] Unknown command: " << cmd << "\n";
    usage(argv[0]);
    return 1;
}
