#include "ore/crypto.hpp"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <limits>
#include <stdexcept>

namespace ore {

Bytes randomBytes(std::size_t size) {
    Bytes out(size);
    if (size == 0) {
        return out;
    }
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return out;
}

Bytes hmacSha256(const Bytes& key, const Bytes& data, std::size_t outLen) {
    if (outLen > SHA256_DIGEST_LENGTH) {
        throw std::invalid_argument("HMAC-SHA256 output cannot exceed 32 bytes");
    }

    unsigned int len = SHA256_DIGEST_LENGTH;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (HMAC(
            EVP_sha256(),
            key.data(),
            static_cast<int>(key.size()),
            data.data(),
            data.size(),
            digest,
            &len
        ) == nullptr) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }

    return Bytes(digest, digest + outLen);
}

Bytes sha256(const Bytes& data) {
    Bytes digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

uint8_t hashToZ3(const Bytes& keyMaterial, const Bytes& nonce) {
    Bytes data;
    appendString(data, "ore.hash.z3");
    appendBytes(data, keyMaterial);
    appendBytes(data, nonce);
    Bytes digest = sha256(data);
    uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | digest[i];
    }
    return static_cast<uint8_t>(value % 3);
}

void appendUint32(Bytes& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

void appendUint64(Bytes& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
    }
}

void appendBytes(Bytes& out, const Bytes& value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("byte string too long to encode");
    }
    appendUint32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void appendString(Bytes& out, const std::string& value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("string too long to encode");
    }
    appendUint32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

Bytes encodeInteger(uint64_t value) {
    Bytes out;
    appendString(out, "ore.integer");
    appendUint64(out, value);
    return out;
}

Bytes encodePrfInput(
    const std::string& domain,
    uint32_t blockBits,
    uint32_t numBlocks,
    const std::vector<uint32_t>& prefix
) {
    Bytes out;
    appendString(out, domain);
    appendUint32(out, blockBits);
    appendUint32(out, numBlocks);
    appendUint32(out, static_cast<uint32_t>(prefix.size()));
    for (uint32_t block : prefix) {
        appendUint32(out, block);
    }
    return out;
}

Bytes encodePrfInput(
    const std::string& domain,
    uint32_t blockBits,
    uint32_t numBlocks,
    const std::vector<uint32_t>& prefix,
    uint32_t block
) {
    Bytes out = encodePrfInput(domain, blockBits, numBlocks, prefix);
    appendUint32(out, block);
    return out;
}

}  // namespace ore
