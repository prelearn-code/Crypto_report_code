#pragma once

#include <cstdint>
#include <vector>

#include "ore/crypto.hpp"

namespace ore {

class SmallDomainPrp {
public:
    SmallDomainPrp(const Bytes& seed, uint32_t domainSize);

    uint32_t permute(uint32_t x) const;
    uint32_t invert(uint32_t y) const;
    uint32_t domainSize() const;

private:
    static uint32_t uniformBelow(const Bytes& seed, uint32_t upperInclusive, uint64_t round);

    std::vector<uint32_t> perm_;
    std::vector<uint32_t> inv_;
};

}  // namespace ore
