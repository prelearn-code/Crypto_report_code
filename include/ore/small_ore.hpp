#pragma once

#include <cstdint>
#include <vector>

#include "ore/crypto.hpp"

namespace ore {

struct SmallORESecretKey {
    Bytes prfKey;
    Bytes prpSeed;
    uint32_t domainSize = 0;
};

struct SmallLeftCiphertext {
    Bytes keyMaterial;
    uint32_t h = 0;
};

struct SmallRightCiphertext {
    Bytes nonce;
    std::vector<uint8_t> values;
};

class SmallORE {
public:
    explicit SmallORE(SmallORESecretKey key);

    static SmallORE setup(uint32_t domainSize, std::size_t keyBytes = 16);

    SmallLeftCiphertext encryptLeft(uint32_t x) const;
    SmallRightCiphertext encryptRight(uint32_t y) const;
    uint32_t decrypt(const SmallRightCiphertext& ciphertext) const;

    const SmallORESecretKey& key() const;

    static uint8_t compare(const SmallLeftCiphertext& left, const SmallRightCiphertext& right);

private:
    SmallORESecretKey key_;
};

}  // namespace ore
