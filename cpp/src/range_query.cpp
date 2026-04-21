#include "ore/range_query.hpp"

#include <algorithm>

namespace ore {

RangeQueryClient::RangeQueryClient(LargeORESecretKey sk, std::uint32_t domain_min, std::uint32_t domain_max)
    : sk_(std::move(sk)), domain_min_(domain_min), domain_max_(domain_max) {}

std::vector<LargeRightCiphertext> RangeQueryClient::setup_token(const std::vector<std::uint32_t>& db_values) const {
    std::vector<std::uint32_t> sorted = db_values;
    std::sort(sorted.begin(), sorted.end());

    std::vector<LargeRightCiphertext> out;
    out.reserve(sorted.size());
    for (auto v : sorted) out.push_back(large_encrypt_right(sk_, v));
    return out;
}

std::pair<LargeLeftCiphertext, LargeLeftCiphertext> RangeQueryClient::range_token(std::uint32_t lo, std::uint32_t hi) const {
    return {large_encrypt_left(sk_, lo), large_encrypt_left(sk_, hi)};
}

std::pair<LargeLeftCiphertext, LargeRightCiphertext> RangeQueryClient::insert_token(std::uint32_t x) const {
    return {large_encrypt_left(sk_, x), large_encrypt_right(sk_, x)};
}

std::pair<LargeLeftCiphertext, LargeRightCiphertext> RangeQueryClient::delete_token(std::uint32_t x) const {
    return {large_encrypt_left(sk_, x), large_encrypt_right(sk_, x)};
}

std::vector<std::uint32_t> RangeQueryClient::decode_response(const std::vector<LargeRightCiphertext>& response) const {
    std::vector<std::uint32_t> out;
    out.reserve(response.size());
    for (const auto& ct_r : response) {
        out.push_back(large_decrypt(sk_, ct_r, domain_min_, domain_max_));
    }
    return out;
}

RangeQueryServer::RangeQueryServer(LargeORESecretKey sk) : sk_(std::move(sk)) {}

void RangeQueryServer::setup(const std::vector<LargeRightCiphertext>& token_right_list) {
    store_ = token_right_list;
}

std::size_t RangeQueryServer::lower_bound(const LargeLeftCiphertext& left_x) const {
    std::size_t lo = 0;
    std::size_t hi = store_.size();
    while (lo < hi) {
        std::size_t mid = (lo + hi) / 2;
        int cmp_res = large_compare(left_x, store_[mid]);
        if (cmp_res == 2) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

std::size_t RangeQueryServer::upper_bound(const LargeLeftCiphertext& left_x) const {
    std::size_t lo = 0;
    std::size_t hi = store_.size();
    while (lo < hi) {
        std::size_t mid = (lo + hi) / 2;
        int cmp_res = large_compare(left_x, store_[mid]);
        if (cmp_res == 1) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

std::vector<LargeRightCiphertext> RangeQueryServer::range_query(const LargeLeftCiphertext& left_lo, const LargeLeftCiphertext& left_hi) const {
    std::size_t lo = lower_bound(left_lo);
    std::size_t hi = upper_bound(left_hi);
    if (lo > hi) return {};
    return std::vector<LargeRightCiphertext>(store_.begin() + static_cast<std::ptrdiff_t>(lo), store_.begin() + static_cast<std::ptrdiff_t>(hi));
}

void RangeQueryServer::insert(const LargeLeftCiphertext& left_x, const LargeRightCiphertext& right_x) {
    std::size_t idx = upper_bound(left_x);
    store_.insert(store_.begin() + static_cast<std::ptrdiff_t>(idx), right_x);
}

bool RangeQueryServer::remove_one(const LargeLeftCiphertext& left_x, const LargeRightCiphertext& right_x) {
    (void)right_x; // right ciphertext is randomized; delete by compare-equality interval.
    std::size_t lo = lower_bound(left_x);
    std::size_t hi = upper_bound(left_x);
    if (lo < hi) {
        store_.erase(store_.begin() + static_cast<std::ptrdiff_t>(lo));
        return true;
    }
    return false;
}

} // namespace ore
