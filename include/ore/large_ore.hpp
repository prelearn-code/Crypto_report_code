#pragma once

#include <cstdint>
#include <vector>

#include "ore/crypto.hpp"

namespace ore {

struct LargeORESecretKey {
    Bytes k1;
    Bytes k2;
    uint32_t blockBits = 8;
    uint32_t numBlocks = 4;

    uint32_t base() const;
    uint64_t maxValue() const;
};

struct LargeLeftBlock {
    Bytes keyMaterial;
    uint32_t h = 0;
};

struct LargeLeftCiphertext {
    uint32_t blockBits = 0;
    uint32_t numBlocks = 0;
    std::vector<LargeLeftBlock> blocks;
};

struct LargeRightCiphertext {
    uint32_t blockBits = 0;
    uint32_t numBlocks = 0;
    Bytes nonce;
    std::vector<std::vector<uint8_t>> blocks;
};

class LargeORE {
public:
    explicit LargeORE(LargeORESecretKey key);

    static LargeORE setup(uint32_t blockBits = 8, uint32_t numBlocks = 4, std::size_t keyBytes = 16);

    LargeLeftCiphertext encryptLeft(uint64_t x) const;
    LargeRightCiphertext encryptRight(uint64_t y) const;
    uint64_t decrypt(const LargeRightCiphertext& ciphertext) const;

    const LargeORESecretKey& key() const;

    static uint8_t compare(const LargeLeftCiphertext& left, const LargeRightCiphertext& right);

private:
    static std::vector<uint32_t> splitBlocks(uint64_t value, uint32_t blockBits, uint32_t numBlocks);
    static uint64_t joinBlocks(const std::vector<uint32_t>& blocks, uint32_t blockBits);
    static void validateParameters(uint32_t blockBits, uint32_t numBlocks);

    LargeORESecretKey key_;
};

}  // namespace ore
