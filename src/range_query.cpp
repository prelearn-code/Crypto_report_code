#include "ore/range_query.hpp"

#include <algorithm>
#include <stdexcept>

namespace ore {

RangeClient::RangeClient(LargeORE ore) : ore_(std::move(ore)) {}

std::vector<StoredRecord> RangeClient::setupDatabase(const std::vector<PlainRecord>& records) const {
    std::vector<PlainRecord> sorted = records;
    std::sort(sorted.begin(), sorted.end(), [](const PlainRecord& a, const PlainRecord& b) {
        if (a.value == b.value) {
            return a.id < b.id;
        }
        return a.value < b.value;
    });

    std::vector<StoredRecord> out;
    out.reserve(sorted.size());
    for (const PlainRecord& record : sorted) {
        out.push_back(StoredRecord{record.id, ore_.encryptRight(record.value)});
    }
    return out;
}

RangeToken RangeClient::rangeToken(uint64_t lower, uint64_t upper) const {
    if (lower > upper) {
        throw std::invalid_argument("range lower bound exceeds upper bound");
    }
    return RangeToken{ore_.encryptLeft(lower), ore_.encryptLeft(upper)};
}

InsertToken RangeClient::insertToken(uint64_t id, uint64_t value) const {
    return InsertToken{id, ore_.encryptLeft(value), ore_.encryptRight(value)};
}

DeleteToken RangeClient::deleteToken(uint64_t value) const {
    return DeleteToken{ore_.encryptLeft(value)};
}

std::vector<PlainRecord> RangeClient::decryptRecords(const std::vector<StoredRecord>& records) const {
    std::vector<PlainRecord> out;
    out.reserve(records.size());
    for (const StoredRecord& record : records) {
        out.push_back(PlainRecord{record.id, ore_.decrypt(record.right)});
    }
    return out;
}

void RangeServer::load(std::vector<StoredRecord> records) {
    records_ = std::move(records);
}

std::vector<StoredRecord> RangeServer::range(const RangeToken& token) const {
    std::size_t first = lowerBound(token.lower);
    std::size_t last = upperBound(token.upper);
    if (first > last) {
        return {};
    }
    return std::vector<StoredRecord>(records_.begin() + first, records_.begin() + last);
}

void RangeServer::insert(const InsertToken& token) {
    std::size_t pos = lowerBound(token.left);
    records_.insert(records_.begin() + pos, StoredRecord{token.id, token.right});
}

std::size_t RangeServer::eraseEqual(const DeleteToken& token) {
    std::size_t first = lowerBound(token.value);
    std::size_t last = first;
    while (last < records_.size() && LargeORE::compare(token.value, records_[last].right) == 0) {
        ++last;
    }
    records_.erase(records_.begin() + first, records_.begin() + last);
    return last - first;
}

std::size_t RangeServer::size() const {
    return records_.size();
}

std::size_t RangeServer::lowerBound(const LargeLeftCiphertext& left) const {
    std::size_t lo = 0;
    std::size_t hi = records_.size();
    while (lo < hi) {
        std::size_t mid = lo + ((hi - lo) / 2);
        uint8_t c = LargeORE::compare(left, records_[mid].right);
        if (c == 1 || c == 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

std::size_t RangeServer::upperBound(const LargeLeftCiphertext& left) const {
    std::size_t lo = 0;
    std::size_t hi = records_.size();
    while (lo < hi) {
        std::size_t mid = lo + ((hi - lo) / 2);
        uint8_t c = LargeORE::compare(left, records_[mid].right);
        if (c == 1) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

}  // namespace ore
