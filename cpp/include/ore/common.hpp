#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace ore {

using Bytes = std::vector<std::uint8_t>;

// cmp3 encoding: 0 = equal, 1 = less, 2 = greater.
inline int cmp3(std::uint32_t x, std::uint32_t y) {
    if (x == y) return 0;
    return x < y ? 1 : 2;
}

inline int decode_cmp3(int v) {
    if (v == 0) return 0;
    if (v == 1) return -1;
    if (v == 2) return 1;
    throw std::invalid_argument("cmp3 value must be in {0,1,2}");
}

Bytes encode_u32(std::uint32_t x);
Bytes encode_blocks(const std::vector<std::uint32_t>& blocks);

Bytes prf_bytes(const Bytes& key, const Bytes& data, std::size_t out_len = 16);
int hash_to_z3(const Bytes& key_material, const Bytes& nonce);
Bytes random_nonce(std::size_t nbytes = 16);
Bytes random_bytes(std::size_t nbytes = 16);

class SmallDomainPRP {
public:
    SmallDomainPRP(Bytes seed, std::size_t domain_size);
    std::uint32_t permute(std::uint32_t x) const;
    std::uint32_t invert(std::uint32_t y) const;

private:
    std::vector<std::uint32_t> perm_;
    std::vector<std::uint32_t> inv_;
};

} // namespace ore
