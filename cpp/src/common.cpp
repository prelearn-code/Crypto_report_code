#include "ore/common.hpp"

#include <algorithm>
#include <chrono>
#include <numeric>
#include <random>

namespace ore {
namespace {

std::uint64_t fnv1a64(const Bytes& data) {
    std::uint64_t h = 1469598103934665603ULL;
    for (auto b : data) {
        h ^= static_cast<std::uint64_t>(b);
        h *= 1099511628211ULL;
    }
    return h;
}

Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

} // namespace

Bytes encode_u32(std::uint32_t x) {
    return Bytes{
        static_cast<std::uint8_t>((x >> 24) & 0xFF),
        static_cast<std::uint8_t>((x >> 16) & 0xFF),
        static_cast<std::uint8_t>((x >> 8) & 0xFF),
        static_cast<std::uint8_t>(x & 0xFF),
    };
}

Bytes encode_blocks(const std::vector<std::uint32_t>& blocks) {
    Bytes out;
    out.reserve(blocks.size() * 4);
    for (auto b : blocks) {
        auto enc = encode_u32(b);
        out.insert(out.end(), enc.begin(), enc.end());
    }
    return out;
}

Bytes prf_bytes(const Bytes& key, const Bytes& data, std::size_t out_len) {
    Bytes seed = concat(key, data);
    std::uint64_t s = fnv1a64(seed);
    std::mt19937_64 gen(s);

    Bytes out(out_len);
    for (std::size_t i = 0; i < out_len; ++i) {
        out[i] = static_cast<std::uint8_t>(gen() & 0xFFU);
    }
    return out;
}

int hash_to_z3(const Bytes& key_material, const Bytes& nonce) {
    Bytes data = concat(key_material, nonce);
    return static_cast<int>(fnv1a64(data) % 3ULL);
}

Bytes random_nonce(std::size_t nbytes) {
    return random_bytes(nbytes);
}

Bytes random_bytes(std::size_t nbytes) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    Bytes out(nbytes);
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(dist(gen));
    }
    return out;
}

SmallDomainPRP::SmallDomainPRP(Bytes seed, std::size_t domain_size)
    : perm_(domain_size), inv_(domain_size) {
    if (domain_size == 0) {
        throw std::invalid_argument("domain_size must be positive");
    }

    std::iota(perm_.begin(), perm_.end(), 0);
    std::uint64_t s = fnv1a64(seed);
    std::mt19937 gen(static_cast<std::uint32_t>(s & 0xFFFFFFFFULL));

    for (std::size_t i = domain_size - 1; i > 0; --i) {
        std::uniform_int_distribution<std::size_t> dist(0, i);
        std::size_t j = dist(gen);
        std::swap(perm_[i], perm_[j]);
    }

    for (std::size_t i = 0; i < domain_size; ++i) {
        inv_[perm_[i]] = static_cast<std::uint32_t>(i);
    }
}

std::uint32_t SmallDomainPRP::permute(std::uint32_t x) const {
    if (x >= perm_.size()) {
        throw std::invalid_argument("x out of range");
    }
    return perm_[x];
}

std::uint32_t SmallDomainPRP::invert(std::uint32_t y) const {
    if (y >= inv_.size()) {
        throw std::invalid_argument("y out of range");
    }
    return inv_[y];
}

} // namespace ore
