#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ore {

using Bytes = std::vector<uint8_t>;

Bytes randomBytes(std::size_t size);
Bytes hmacSha256(const Bytes& key, const Bytes& data, std::size_t outLen = 16);
Bytes sha256(const Bytes& data);
uint8_t hashToZ3(const Bytes& keyMaterial, const Bytes& nonce);

void appendUint32(Bytes& out, uint32_t value);
void appendUint64(Bytes& out, uint64_t value);
void appendBytes(Bytes& out, const Bytes& value);
void appendString(Bytes& out, const std::string& value);

Bytes encodeInteger(uint64_t value);
Bytes encodePrfInput(
    const std::string& domain,
    uint32_t blockBits,
    uint32_t numBlocks,
    const std::vector<uint32_t>& prefix
);
Bytes encodePrfInput(
    const std::string& domain,
    uint32_t blockBits,
    uint32_t numBlocks,
    const std::vector<uint32_t>& prefix,
    uint32_t block
);

}  // namespace ore
