#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ore/large_ore.hpp"

namespace ore {

struct PlainRecord {
    uint64_t id = 0;
    uint64_t value = 0;
};

struct StoredRecord {
    uint64_t id = 0;
    LargeRightCiphertext right;
};

struct RangeToken {
    LargeLeftCiphertext lower;
    LargeLeftCiphertext upper;
};

struct InsertToken {
    uint64_t id = 0;
    LargeLeftCiphertext left;
    LargeRightCiphertext right;
};

struct DeleteToken {
    LargeLeftCiphertext value;
};

class RangeClient {
public:
    explicit RangeClient(LargeORE ore);

    std::vector<StoredRecord> setupDatabase(const std::vector<PlainRecord>& records) const;
    RangeToken rangeToken(uint64_t lower, uint64_t upper) const;
    InsertToken insertToken(uint64_t id, uint64_t value) const;
    DeleteToken deleteToken(uint64_t value) const;
    std::vector<PlainRecord> decryptRecords(const std::vector<StoredRecord>& records) const;

private:
    LargeORE ore_;
};

class RangeServer {
public:
    void load(std::vector<StoredRecord> records);
    std::vector<StoredRecord> range(const RangeToken& token) const;
    void insert(const InsertToken& token);
    std::size_t eraseEqual(const DeleteToken& token);
    std::size_t size() const;

private:
    std::size_t lowerBound(const LargeLeftCiphertext& left) const;
    std::size_t upperBound(const LargeLeftCiphertext& left) const;

    std::vector<StoredRecord> records_;
};

}  // namespace ore
