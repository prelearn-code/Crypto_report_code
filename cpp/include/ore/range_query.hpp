#pragma once

#include "ore/large_ore.hpp"

#include <cstdint>
#include <vector>

namespace ore {

class RangeQueryClient {
public:
    RangeQueryClient(LargeORESecretKey sk, std::uint32_t domain_min, std::uint32_t domain_max);

    std::vector<LargeRightCiphertext> setup_token(const std::vector<std::uint32_t>& db_values) const;
    std::pair<LargeLeftCiphertext, LargeLeftCiphertext> range_token(std::uint32_t lo, std::uint32_t hi) const;
    std::pair<LargeLeftCiphertext, LargeRightCiphertext> insert_token(std::uint32_t x) const;
    std::pair<LargeLeftCiphertext, LargeRightCiphertext> delete_token(std::uint32_t x) const;
    std::vector<std::uint32_t> decode_response(const std::vector<LargeRightCiphertext>& response) const;

private:
    LargeORESecretKey sk_;
    std::uint32_t domain_min_;
    std::uint32_t domain_max_;
};

class RangeQueryServer {
public:
    explicit RangeQueryServer(LargeORESecretKey sk);

    void setup(const std::vector<LargeRightCiphertext>& token_right_list);
    std::vector<LargeRightCiphertext> range_query(const LargeLeftCiphertext& left_lo, const LargeLeftCiphertext& left_hi) const;
    void insert(const LargeLeftCiphertext& left_x, const LargeRightCiphertext& right_x);
    bool remove_one(const LargeLeftCiphertext& left_x, const LargeRightCiphertext& right_x);

private:
    std::size_t lower_bound(const LargeLeftCiphertext& left_x) const;
    std::size_t upper_bound(const LargeLeftCiphertext& left_x) const;

    LargeORESecretKey sk_;
    std::vector<LargeRightCiphertext> store_;
};

} // namespace ore
