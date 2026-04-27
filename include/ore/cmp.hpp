#pragma once

#include <cstdint>
#include <stdexcept>

namespace ore {

inline uint8_t cmp3(uint64_t x, uint64_t y) {
    if (x == y) {
        return 0;
    }
    return x < y ? 1 : 2;
}

inline int decodeCmp3(uint8_t value) {
    if (value == 0) {
        return 0;
    }
    if (value == 1) {
        return -1;
    }
    if (value == 2) {
        return 1;
    }
    throw std::invalid_argument("invalid cmp3 value");
}

}  // namespace ore
