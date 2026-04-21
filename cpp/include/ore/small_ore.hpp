#pragma once

#include "ore/common.hpp"

#include <cstdint>
#include <vector>

namespace ore {

struct SmallORESecretKey {
    Bytes prf_key;
    Bytes prp_seed;
    std::size_t domain_size;
};

struct SmallLeftCiphertext {
    Bytes key_material;
    std::uint32_t h;
};

struct SmallRightCiphertext {
    Bytes nonce;
    std::vector<int> v;
};

SmallORESecretKey small_setup(std::size_t domain_size, std::size_t key_bytes = 16);
SmallLeftCiphertext small_encrypt_left(const SmallORESecretKey& sk, std::uint32_t x);
SmallRightCiphertext small_encrypt_right(const SmallORESecretKey& sk, std::uint32_t y);
int small_compare(const SmallLeftCiphertext& ct_l, const SmallRightCiphertext& ct_r);
std::uint32_t small_decrypt(const SmallORESecretKey& sk, const SmallRightCiphertext& ct_r);

} // namespace ore
