#include "ore/large_ore.hpp"

#include <algorithm>

namespace ore {
namespace {

Bytes derive_prp_seed(const Bytes& k2, const std::vector<std::uint32_t>& prefix) {
    Bytes data{'P', 'R', 'P', '|'};
    auto enc = encode_blocks(prefix);
    data.insert(data.end(), enc.begin(), enc.end());
    return prf_bytes(k2, data, 16);
}

Bytes derive_k1_material(const Bytes& k1, const std::vector<std::uint32_t>& prefix, std::uint32_t j) {
    Bytes data{'K', '1', '|'};
    auto enc = encode_blocks(prefix);
    auto enc_j = encode_u32(j);
    data.insert(data.end(), enc.begin(), enc.end());
    data.push_back('|');
    data.insert(data.end(), enc_j.begin(), enc_j.end());
    return prf_bytes(k1, data, 16);
}

SmallDomainPRP prefix_prp(const Bytes& k2, const std::vector<std::uint32_t>& prefix, std::uint32_t d) {
    return SmallDomainPRP(derive_prp_seed(k2, prefix), d);
}

} // namespace

std::vector<std::uint32_t> int_to_base_d_blocks(std::uint32_t x, std::uint32_t d, std::uint32_t n) {
    if (d <= 1) throw std::invalid_argument("d must be > 1");
    if (n == 0) throw std::invalid_argument("n must be positive");

    std::uint64_t domain = 1;
    for (std::uint32_t i = 0; i < n; ++i) domain *= d;
    if (x >= domain) throw std::invalid_argument("x out of representable range");

    std::vector<std::uint32_t> blocks(n, 0);
    std::uint32_t cur = x;
    for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
        blocks[static_cast<std::size_t>(i)] = cur % d;
        cur /= d;
    }
    return blocks;
}

std::uint32_t base_d_blocks_to_int(const std::vector<std::uint32_t>& blocks, std::uint32_t d) {
    if (d <= 1) throw std::invalid_argument("d must be > 1");

    std::uint64_t out = 0;
    for (auto b : blocks) {
        if (b >= d) throw std::invalid_argument("block out of range");
        out = out * d + b;
    }
    return static_cast<std::uint32_t>(out);
}

LargeORESecretKey large_setup(std::uint32_t d, std::uint32_t n, std::size_t key_bytes) {
    if (d <= 1) throw std::invalid_argument("d must be > 1");
    if (n == 0) throw std::invalid_argument("n must be positive");
    if (key_bytes == 0) throw std::invalid_argument("key_bytes must be positive");

    return LargeORESecretKey{random_bytes(key_bytes), random_bytes(key_bytes), d, n};
}

LargeLeftCiphertext large_encrypt_left(const LargeORESecretKey& sk, std::uint32_t x) {
    auto x_blocks = int_to_base_d_blocks(x, sk.d, sk.n);
    std::vector<std::uint32_t> prefix;
    std::vector<LargeLeftBlock> out;

    for (auto xi : x_blocks) {
        SmallDomainPRP prp = prefix_prp(sk.k2, prefix, sk.d);
        std::uint32_t h = prp.permute(xi);
        Bytes km = derive_k1_material(sk.k1, prefix, h);
        out.push_back(LargeLeftBlock{km, h});
        prefix.push_back(xi);
    }

    return LargeLeftCiphertext{out};
}

LargeRightCiphertext large_encrypt_right(const LargeORESecretKey& sk, std::uint32_t y) {
    auto y_blocks = int_to_base_d_blocks(y, sk.d, sk.n);
    Bytes nonce = random_nonce(16);

    std::vector<std::uint32_t> prefix;
    std::vector<std::vector<int>> tables;

    for (auto yi : y_blocks) {
        SmallDomainPRP prp = prefix_prp(sk.k2, prefix, sk.d);
        std::vector<int> row;
        row.reserve(sk.d);

        for (std::uint32_t j = 0; j < sk.d; ++j) {
            std::uint32_t candidate = prp.invert(j);
            int c = cmp3(candidate, yi);
            int mask = hash_to_z3(derive_k1_material(sk.k1, prefix, j), nonce);
            row.push_back((c + mask) % 3);
        }

        tables.push_back(row);
        prefix.push_back(yi);
    }

    return LargeRightCiphertext{nonce, tables};
}

int large_compare(const LargeLeftCiphertext& ct_l, const LargeRightCiphertext& ct_r) {
    if (ct_l.blocks.size() != ct_r.tables.size()) {
        throw std::invalid_argument("ciphertext block count mismatch");
    }

    for (std::size_t i = 0; i < ct_l.blocks.size(); ++i) {
        const auto& blk = ct_l.blocks[i];
        const auto& table = ct_r.tables[i];
        if (blk.h >= table.size()) throw std::invalid_argument("left block index out of range");

        int value = table[blk.h];
        int mask = hash_to_z3(blk.key_material, ct_r.nonce);
        int res = (value - mask + 3) % 3;
        if (res != 0) return res;
    }

    return 0;
}

std::uint32_t large_decrypt(const LargeORESecretKey& sk, const LargeRightCiphertext& ct_r, std::uint32_t domain_min, std::uint32_t domain_max) {
    std::uint32_t lo = domain_min;
    std::uint32_t hi = domain_max;

    while (lo <= hi) {
        std::uint32_t mid = lo + (hi - lo) / 2;
        int res = large_compare(large_encrypt_left(sk, mid), ct_r);
        if (res == 0) return mid;
        if (res == 1) {
            lo = mid + 1;
        } else {
            if (mid == 0) break;
            hi = mid - 1;
        }
    }

    throw std::runtime_error("plaintext not found");
}

} // namespace ore
