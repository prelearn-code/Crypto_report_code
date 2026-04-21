#include "ore/small_ore.hpp"

namespace ore {

SmallORESecretKey small_setup(std::size_t domain_size, std::size_t key_bytes) {
    if (domain_size == 0) throw std::invalid_argument("domain_size must be positive");
    if (key_bytes == 0) throw std::invalid_argument("key_bytes must be positive");

    return SmallORESecretKey{random_bytes(key_bytes), random_bytes(key_bytes), domain_size};
}

SmallLeftCiphertext small_encrypt_left(const SmallORESecretKey& sk, std::uint32_t x) {
    SmallDomainPRP prp(sk.prp_seed, sk.domain_size);
    std::uint32_t h = prp.permute(x);
    Bytes key_material = prf_bytes(sk.prf_key, encode_u32(h), 16);
    return SmallLeftCiphertext{key_material, h};
}

SmallRightCiphertext small_encrypt_right(const SmallORESecretKey& sk, std::uint32_t y) {
    if (y >= sk.domain_size) throw std::invalid_argument("y out of range");

    SmallDomainPRP prp(sk.prp_seed, sk.domain_size);
    Bytes nonce = random_nonce(16);
    std::vector<int> v;
    v.reserve(sk.domain_size);

    for (std::uint32_t i = 0; i < sk.domain_size; ++i) {
        std::uint32_t candidate = prp.invert(i);
        int c = cmp3(candidate, y);
        Bytes fk_i = prf_bytes(sk.prf_key, encode_u32(i), 16);
        int masked = (c + hash_to_z3(fk_i, nonce)) % 3;
        v.push_back(masked);
    }

    return SmallRightCiphertext{nonce, v};
}

int small_compare(const SmallLeftCiphertext& ct_l, const SmallRightCiphertext& ct_r) {
    if (ct_l.h >= ct_r.v.size()) throw std::invalid_argument("left index out of range");
    int value = ct_r.v[ct_l.h];
    int mask = hash_to_z3(ct_l.key_material, ct_r.nonce);
    return (value - mask + 3) % 3;
}

std::uint32_t small_decrypt(const SmallORESecretKey& sk, const SmallRightCiphertext& ct_r) {
    for (std::uint32_t x = 0; x < sk.domain_size; ++x) {
        if (small_compare(small_encrypt_left(sk, x), ct_r) == 0) {
            return x;
        }
    }
    throw std::runtime_error("plaintext not found");
}

} // namespace ore
