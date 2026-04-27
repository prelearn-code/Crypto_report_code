#include "ore/prp.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace ore {

SmallDomainPrp::SmallDomainPrp(const Bytes& seed, uint32_t domainSize) {
    if (domainSize == 0) {
        throw std::invalid_argument("PRP domain size must be positive");
    }
    perm_.resize(domainSize);
    inv_.resize(domainSize);
    for (uint32_t i = 0; i < domainSize; ++i) {
        perm_[i] = i;
    }

    uint64_t round = 0;
    for (uint32_t i = domainSize - 1; i > 0; --i) {
        uint32_t j = uniformBelow(seed, i, round++);
        std::swap(perm_[i], perm_[j]);
    }
    for (uint32_t i = 0; i < domainSize; ++i) {
        inv_[perm_[i]] = i;
    }
}

uint32_t SmallDomainPrp::permute(uint32_t x) const {
    if (x >= perm_.size()) {
        throw std::out_of_range("PRP input out of range");
    }
    return perm_[x];
}

uint32_t SmallDomainPrp::invert(uint32_t y) const {
    if (y >= inv_.size()) {
        throw std::out_of_range("PRP output out of range");
    }
    return inv_[y];
}

uint32_t SmallDomainPrp::domainSize() const {
    return static_cast<uint32_t>(perm_.size());
}

uint32_t SmallDomainPrp::uniformBelow(const Bytes& seed, uint32_t upperInclusive, uint64_t round) {
    const uint64_t bound = static_cast<uint64_t>(upperInclusive) + 1;
    const uint64_t limit = std::numeric_limits<uint64_t>::max()
        - (std::numeric_limits<uint64_t>::max() % bound);

    for (uint32_t counter = 0;; ++counter) {
        Bytes data;
        appendString(data, "ore.prp.fisher-yates");
        appendUint64(data, round);
        appendUint32(data, counter);
        Bytes digest = hmacSha256(seed, data, 16);

        uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value = (value << 8) | digest[i];
        }
        if (value < limit) {
            return static_cast<uint32_t>(value % bound);
        }
    }
}

}  // namespace ore
