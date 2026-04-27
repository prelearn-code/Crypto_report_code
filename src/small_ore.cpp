#include "ore/small_ore.hpp"

#include <stdexcept>

#include "ore/cmp.hpp"
#include "ore/prp.hpp"

namespace ore {

SmallORE::SmallORE(SmallORESecretKey key) : key_(std::move(key)) {
    if (key_.prfKey.empty() || key_.prpSeed.empty()) {
        throw std::invalid_argument("small ORE keys must be non-empty");
    }
    if (key_.domainSize == 0) {
        throw std::invalid_argument("small ORE domain must be positive");
    }
}

SmallORE SmallORE::setup(uint32_t domainSize, std::size_t keyBytes) {
    if (domainSize == 0) {
        throw std::invalid_argument("domain size must be positive");
    }
    if (keyBytes == 0) {
        throw std::invalid_argument("key size must be positive");
    }
    return SmallORE(SmallORESecretKey{
        randomBytes(keyBytes),
        randomBytes(keyBytes),
        domainSize,
    });
}

SmallLeftCiphertext SmallORE::encryptLeft(uint32_t x) const {
    if (x >= key_.domainSize) {
        throw std::out_of_range("left plaintext out of range");
    }
    SmallDomainPrp prp(key_.prpSeed, key_.domainSize);
    uint32_t h = prp.permute(x);
    Bytes material = hmacSha256(key_.prfKey, encodeInteger(h), 16);
    return SmallLeftCiphertext{material, h};
}

SmallRightCiphertext SmallORE::encryptRight(uint32_t y) const {
    if (y >= key_.domainSize) {
        throw std::out_of_range("right plaintext out of range");
    }

    SmallDomainPrp prp(key_.prpSeed, key_.domainSize);
    Bytes nonce = randomBytes(16);
    std::vector<uint8_t> values;
    values.reserve(key_.domainSize);

    for (uint32_t i = 0; i < key_.domainSize; ++i) {
        uint32_t candidate = prp.invert(i);
        uint8_t plainCmp = cmp3(candidate, y);
        Bytes material = hmacSha256(key_.prfKey, encodeInteger(i), 16);
        uint8_t mask = hashToZ3(material, nonce);
        values.push_back(static_cast<uint8_t>((plainCmp + mask) % 3));
    }

    return SmallRightCiphertext{nonce, values};
}

uint8_t SmallORE::compare(const SmallLeftCiphertext& left, const SmallRightCiphertext& right) {
    if (left.h >= right.values.size()) {
        throw std::out_of_range("left ciphertext index out of right ciphertext range");
    }
    uint8_t value = right.values[left.h];
    uint8_t mask = hashToZ3(left.keyMaterial, right.nonce);
    return static_cast<uint8_t>((value + 3 - mask) % 3);
}

uint32_t SmallORE::decrypt(const SmallRightCiphertext& ciphertext) const {
    for (uint32_t x = 0; x < key_.domainSize; ++x) {
        if (compare(encryptLeft(x), ciphertext) == 0) {
            return x;
        }
    }
    throw std::runtime_error("small ORE ciphertext did not decrypt");
}

const SmallORESecretKey& SmallORE::key() const {
    return key_;
}

}  // namespace ore
