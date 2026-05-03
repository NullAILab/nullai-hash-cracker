/*
 * hash.cpp — Self-contained MD5, SHA-1, SHA-256 implementations.
 *
 * All three algorithms are implemented from their respective RFCs:
 *   MD5   — RFC 1321
 *   SHA-1 — FIPS PUB 180-4
 *   SHA-256 — FIPS PUB 180-4
 *
 * No external library dependencies — pure C++17.
 */

#include "hash.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <array>
#include <vector>

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

static std::string to_hex(const uint8_t* buf, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(buf[i]);
    return ss.str();
}

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// ─────────────────────────────────────────────────────────────
// MD5  (RFC 1321)
// ─────────────────────────────────────────────────────────────

static const uint32_t MD5_T[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
};

static const int MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
};

std::string md5_hex(const std::string& input) {
    // Initial hash values
    uint32_t a0=0x67452301, b0=0xefcdab89, c0=0x98badcfe, d0=0x10325476;

    // Pre-processing: pad message
    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bit_len = static_cast<uint64_t>(input.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 0; i < 8; ++i)
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

    // Process each 512-bit block
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; ++i)
            M[i] = static_cast<uint32_t>(msg[off + 4*i])
                 | (static_cast<uint32_t>(msg[off + 4*i+1]) << 8)
                 | (static_cast<uint32_t>(msg[off + 4*i+2]) << 16)
                 | (static_cast<uint32_t>(msg[off + 4*i+3]) << 24);

        uint32_t A=a0, B=b0, C=c0, D=d0;

        for (int i = 0; i < 64; ++i) {
            uint32_t F; int g;
            if      (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5*i+1) % 16; }
            else if (i < 48) { F = B ^ C ^ D;           g = (3*i+5) % 16; }
            else             { F = C ^ (B | ~D);         g = (7*i)   % 16; }
            F = F + A + MD5_T[i] + M[g];
            A = D; D = C; C = B;
            B = B + rotl32(F, MD5_S[i]);
        }
        a0+=A; b0+=B; c0+=C; d0+=D;
    }

    uint8_t digest[16];
    auto write_le = [](uint8_t* p, uint32_t v){
        p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;
    };
    write_le(digest+0,  a0);
    write_le(digest+4,  b0);
    write_le(digest+8,  c0);
    write_le(digest+12, d0);
    return to_hex(digest, 16);
}

// ─────────────────────────────────────────────────────────────
// SHA-1 (FIPS 180-4)
// ─────────────────────────────────────────────────────────────

std::string sha1_hex(const std::string& input) {
    uint32_t h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE,
             h3=0x10325476, h4=0xC3D2E1F0;

    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bit_len = static_cast<uint64_t>(input.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (msg[off+4*i]<<24)|(msg[off+4*i+1]<<16)|
                   (msg[off+4*i+2]<<8)|msg[off+4*i+3];
        for (int i = 16; i < 80; ++i)
            w[i] = rotl32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if      (i < 20){ f=(b&c)|(~b&d);         k=0x5A827999; }
            else if (i < 40){ f=b^c^d;                 k=0x6ED9EBA1; }
            else if (i < 60){ f=(b&c)|(b&d)|(c&d);    k=0x8F1BBCDC; }
            else             { f=b^c^d;                k=0xCA62C1D6; }
            uint32_t tmp = rotl32(a,5)+f+e+k+w[i];
            e=d; d=c; c=rotl32(b,30); b=a; a=tmp;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e;
    }

    uint8_t digest[20];
    auto write_be = [](uint8_t* p, uint32_t v){
        p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;
    };
    write_be(digest+0,  h0);
    write_be(digest+4,  h1);
    write_be(digest+8,  h2);
    write_be(digest+12, h3);
    write_be(digest+16, h4);
    return to_hex(digest, 20);
}

// ─────────────────────────────────────────────────────────────
// SHA-256 (FIPS 180-4)
// ─────────────────────────────────────────────────────────────

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static const uint32_t SHA256_H0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
};

std::string sha256_hex(const std::string& input) {
    uint32_t h[8];
    for (int i=0;i<8;++i) h[i]=SHA256_H0[i];

    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bit_len = static_cast<uint64_t>(input.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i]=(msg[off+4*i]<<24)|(msg[off+4*i+1]<<16)|
                 (msg[off+4*i+2]<<8)|msg[off+4*i+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],
                 e=h[4],f=h[5],g=h[6],hh=h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1   = rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
            uint32_t ch   = (e&f)^(~e&g);
            uint32_t tmp1 = hh+S1+ch+SHA256_K[i]+w[i];
            uint32_t S0   = rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
            uint32_t maj  = (a&b)^(a&c)^(b&c);
            uint32_t tmp2 = S0+maj;
            hh=g; g=f; f=e; e=d+tmp1;
            d=c; c=b; b=a; a=tmp1+tmp2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
        h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }

    uint8_t digest[32];
    for (int i=0;i<8;++i){
        digest[4*i]   = h[i]>>24;
        digest[4*i+1] = h[i]>>16;
        digest[4*i+2] = h[i]>>8;
        digest[4*i+3] = h[i];
    }
    return to_hex(digest, 32);
}

// ─────────────────────────────────────────────────────────────
// Hash identification
// ─────────────────────────────────────────────────────────────

std::string identify_hash(const std::string& hex) {
    // Verify all hex characters first
    for (char c : hex)
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return "unknown";

    switch (hex.size()) {
        case 32:  return "md5";
        case 40:  return "sha1";
        case 64:  return "sha256";
        default:  return "unknown";
    }
}
