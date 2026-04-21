#pragma once

#include "ore/small_ore.hpp"

#include <cstdint>
#include <vector>

namespace ore {

struct LargeORESecretKey {
    Bytes k1;
    Bytes k2;
    std::uint32_t d;
    std::uint32_t n;
};

struct LargeLeftBlock {
    Bytes key_material;
    std::uint32_t h;
};

struct LargeLeftCiphertext {
    std::vector<LargeLeftBlock> blocks;
};

struct LargeRightCiphertext {
    Bytes nonce;
    std::vector<std::vector<int>> tables;
};

std::vector<std::uint32_t> int_to_base_d_blocks(std::uint32_t x, std::uint32_t d, std::uint32_t n);
std::uint32_t base_d_blocks_to_int(const std::vector<std::uint32_t>& blocks, std::uint32_t d);

LargeORESecretKey large_setup(std::uint32_t d, std::uint32_t n, std::size_t key_bytes = 16);
LargeLeftCiphertext large_encrypt_left(const LargeORESecretKey& sk, std::uint32_t x);
LargeRightCiphertext large_encrypt_right(const LargeORESecretKey& sk, std::uint32_t y);
int large_compare(const LargeLeftCiphertext& ct_l, const LargeRightCiphertext& ct_r);
std::uint32_t large_decrypt(const LargeORESecretKey& sk, const LargeRightCiphertext& ct_r, std::uint32_t domain_min, std::uint32_t domain_max);

} // namespace ore
