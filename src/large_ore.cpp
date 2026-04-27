#include "ore/large_ore.hpp"

#include <limits>
#include <stdexcept>

#include "ore/cmp.hpp"
#include "ore/prp.hpp"

namespace ore {

uint32_t LargeORESecretKey::base() const {
    if (blockBits == 32) {
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(1u << blockBits);
}

uint64_t LargeORESecretKey::maxValue() const {
    const uint32_t totalBits = blockBits * numBlocks;
    if (totalBits >= 64) {
        return std::numeric_limits<uint64_t>::max();
    }
    return (uint64_t{1} << totalBits) - 1;
}

LargeORE::LargeORE(LargeORESecretKey key) : key_(std::move(key)) {
    validateParameters(key_.blockBits, key_.numBlocks);
    if (key_.k1.empty() || key_.k2.empty()) {
        throw std::invalid_argument("large ORE keys must be non-empty");
    }
}

LargeORE LargeORE::setup(uint32_t blockBits, uint32_t numBlocks, std::size_t keyBytes) {
    validateParameters(blockBits, numBlocks);
    if (keyBytes == 0) {
        throw std::invalid_argument("key size must be positive");
    }
    return LargeORE(LargeORESecretKey{
        randomBytes(keyBytes),
        randomBytes(keyBytes),
        blockBits,
        numBlocks,
    });
}

LargeLeftCiphertext LargeORE::encryptLeft(uint64_t x) const {
    if (x > key_.maxValue()) {
        throw std::out_of_range("left plaintext exceeds configured domain");
    }

    const uint32_t base = key_.base();
    std::vector<uint32_t> blocks = splitBlocks(x, key_.blockBits, key_.numBlocks);
    std::vector<uint32_t> prefix;
    std::vector<LargeLeftBlock> out;
    out.reserve(key_.numBlocks);

    for (uint32_t i = 0; i < key_.numBlocks; ++i) {
        Bytes prpSeed = hmacSha256(
            key_.k2,
            encodePrfInput("large.prp.prefix", key_.blockBits, key_.numBlocks, prefix),
            16
        );
        SmallDomainPrp prp(prpSeed, base);
        uint32_t h = prp.permute(blocks[i]);
        Bytes material = hmacSha256(
            key_.k1,
            encodePrfInput("large.compare.key", key_.blockBits, key_.numBlocks, prefix, h),
            16
        );
        out.push_back(LargeLeftBlock{material, h});
        prefix.push_back(blocks[i]);
    }

    return LargeLeftCiphertext{key_.blockBits, key_.numBlocks, out};
}

LargeRightCiphertext LargeORE::encryptRight(uint64_t y) const {
    if (y > key_.maxValue()) {
        throw std::out_of_range("right plaintext exceeds configured domain");
    }

    const uint32_t base = key_.base();
    std::vector<uint32_t> blocks = splitBlocks(y, key_.blockBits, key_.numBlocks);
    std::vector<uint32_t> prefix;
    Bytes nonce = randomBytes(16);

    std::vector<std::vector<uint8_t>> outBlocks;
    outBlocks.reserve(key_.numBlocks);

    for (uint32_t i = 0; i < key_.numBlocks; ++i) {
        Bytes prpSeed = hmacSha256(
            key_.k2,
            encodePrfInput("large.prp.prefix", key_.blockBits, key_.numBlocks, prefix),
            16
        );
        SmallDomainPrp prp(prpSeed, base);

        std::vector<uint8_t> values;
        values.reserve(base);
        for (uint32_t j = 0; j < base; ++j) {
            uint32_t candidate = prp.invert(j);
            uint8_t plainCmp = cmp3(candidate, blocks[i]);
            Bytes material = hmacSha256(
                key_.k1,
                encodePrfInput("large.compare.key", key_.blockBits, key_.numBlocks, prefix, j),
                16
            );
            uint8_t mask = hashToZ3(material, nonce);
            values.push_back(static_cast<uint8_t>((plainCmp + mask) % 3));
        }

        outBlocks.push_back(std::move(values));
        prefix.push_back(blocks[i]);
    }

    return LargeRightCiphertext{key_.blockBits, key_.numBlocks, nonce, outBlocks};
}

uint8_t LargeORE::compare(const LargeLeftCiphertext& left, const LargeRightCiphertext& right) {
    if (left.blockBits != right.blockBits || left.numBlocks != right.numBlocks) {
        throw std::invalid_argument("ciphertext parameters do not match");
    }
    if (left.blocks.size() != left.numBlocks || right.blocks.size() != right.numBlocks) {
        throw std::invalid_argument("malformed large ORE ciphertext");
    }

    for (uint32_t i = 0; i < left.numBlocks; ++i) {
        uint32_t h = left.blocks[i].h;
        if (h >= right.blocks[i].size()) {
            throw std::out_of_range("left block index out of right block range");
        }
        uint8_t value = right.blocks[i][h];
        uint8_t mask = hashToZ3(left.blocks[i].keyMaterial, right.nonce);
        uint8_t plainCmp = static_cast<uint8_t>((value + 3 - mask) % 3);
        if (plainCmp != 0) {
            return plainCmp;
        }
    }

    return 0;
}

uint64_t LargeORE::decrypt(const LargeRightCiphertext& ciphertext) const {
    if (ciphertext.blockBits != key_.blockBits || ciphertext.numBlocks != key_.numBlocks) {
        throw std::invalid_argument("ciphertext parameters do not match key");
    }

    uint64_t low = 0;
    uint64_t high = key_.maxValue();
    while (low <= high) {
        uint64_t mid = low + ((high - low) / 2);
        uint8_t c = compare(encryptLeft(mid), ciphertext);
        if (c == 0) {
            return mid;
        }
        if (c == 1) {
            if (mid == std::numeric_limits<uint64_t>::max()) {
                break;
            }
            low = mid + 1;
        } else {
            if (mid == 0) {
                break;
            }
            high = mid - 1;
        }
    }

    throw std::runtime_error("large ORE ciphertext did not decrypt");
}

const LargeORESecretKey& LargeORE::key() const {
    return key_;
}

std::vector<uint32_t> LargeORE::splitBlocks(uint64_t value, uint32_t blockBits, uint32_t numBlocks) {
    validateParameters(blockBits, numBlocks);

    std::vector<uint32_t> out(numBlocks);
    uint64_t mask = (uint64_t{1} << blockBits) - 1;
    for (uint32_t i = 0; i < numBlocks; ++i) {
        uint32_t shift = blockBits * (numBlocks - 1 - i);
        out[i] = static_cast<uint32_t>((value >> shift) & mask);
    }
    return out;
}

uint64_t LargeORE::joinBlocks(const std::vector<uint32_t>& blocks, uint32_t blockBits) {
    uint64_t value = 0;
    uint64_t maxBlock = (uint64_t{1} << blockBits) - 1;
    for (uint32_t block : blocks) {
        if (block > maxBlock) {
            throw std::out_of_range("block exceeds base");
        }
        value = (value << blockBits) | block;
    }
    return value;
}

void LargeORE::validateParameters(uint32_t blockBits, uint32_t numBlocks) {
    if (blockBits == 0 || blockBits > 16) {
        throw std::invalid_argument("blockBits must be in [1, 16]");
    }
    if (numBlocks == 0) {
        throw std::invalid_argument("numBlocks must be positive");
    }
    if (blockBits * numBlocks > 63) {
        throw std::invalid_argument("this implementation supports up to 63-bit domains");
    }
}

}  // namespace ore
